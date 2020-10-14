use crate::base::credential::Credential;
use crate::base::base64::urlsafe;
use crate::internal::http::{boundary_str, Multipart};
use log::{debug, info, trace, warn};
use once_cell::sync::Lazy;
use positioned_io::ReadAt;
use rand::{seq::SliceRandom, thread_rng};
use reqwest::blocking::Client;
use serde::Deserialize;
use std::convert::TryFrom;
use std::env;
use std::io::{Error, ErrorKind, Read};
use std::path::PathBuf;
use std::result::Result;
use std::time::{SystemTime, SystemTimeError, Duration, UNIX_EPOCH};
use std::thread;
use url::Url;

use std::iter::FromIterator;

use sha1::{Sha1, Digest};

use bytes::Buf;
use std::io::Cursor;
use std::fs;

pub fn sign_download_url_with_deadline(
    c: &Credential,
    url: Url,
    deadline: SystemTime,
    only_path: bool,
) -> Result<String, SystemTimeError> {
    let mut signed_url = {
        let mut s = String::with_capacity(2048);
        s.push_str(url.as_str());
        s
    };
    let mut to_sign = {
        let mut s = String::with_capacity(2048);
        if only_path {
            s.push_str(url.path());
            if let Some(query) = url.query() {
                s.push('?');
                s.push_str(query);
            }
        } else {
            s.push_str(url.as_str());
        }
        s
    };

    if to_sign.contains('?') {
        to_sign.push_str("&e=");
        signed_url.push_str("&e=");
    } else {
        to_sign.push_str("?e=");
        signed_url.push_str("?e=");
    }

    let deadline = u32::try_from(deadline.duration_since(UNIX_EPOCH)?.as_secs())
        .unwrap_or(std::u32::MAX)
        .to_string();
    to_sign.push_str(&deadline);
    signed_url.push_str(&deadline);
    signed_url.push_str("&token=");
    signed_url.push_str(&c.sign(to_sign.as_bytes()));
    Ok(signed_url)
}

pub fn sign_download_url_with_lifetime(
    c: &Credential,
    url: Url,
    lifetime: Duration,
    only_path: bool,
) -> Result<String, SystemTimeError> {
    let deadline = SystemTime::now() + lifetime;
    sign_download_url_with_deadline(c, url, deadline, only_path)
}

fn data_hash(data: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.input(data);
    let result = hasher.result();
    return hex::encode(result.as_slice());
}

fn gen_range(range: &Vec<(u64, u64)>) -> String {
    let mut ar: Vec<String> = Vec::new();
    for i in range {
        let start = i.0;
        let end = start + i.1 - 1;
        let b = format!("{}-{}", start, end).to_owned();
        ar.push(b.to_owned());
    }
    ar.join(",")
}

fn parse_range(range_str: &str) -> std::io::Result<(u64, u64)>{
    let s1: Vec<&str> = range_str.split(" ").collect();
    let s2: Vec<&str> = s1[s1.len()-1].split("/").collect();
    let s3: Vec<&str> = s2[0].split("-").collect();
    let e = Error::new(ErrorKind::InvalidInput, range_str);
    if s3.len() != 2 {
        return Err(e);
    }

    let start = s3[0].parse::<u64>();
    if start.is_err() {
        return Err(e);
    }
    let end =  s3[1].parse::<u64>();
    if end.is_err() {
        return Err(e);
    }
    let start = start.unwrap();
    let end = end.unwrap();
    return Ok((start, end-start+1));
}

fn is_debug() -> bool {
    env::var("QINIU_DEBUG").is_ok()
}

const UA:&str = "QiniuRustDownload/10.12";

fn file_name(url: &str) -> String {
    let ss:Vec<&str> = url.split("/").collect();
    return format!("dump_body_{}", ss[ss.len()-1]);
}

#[derive(Debug)]
pub struct RangeReader {
    urls: Vec<String>,
    tries: usize,
    client: Client,
}

impl RangeReader {
    pub fn new(urls: &[String], tries: usize) -> RangeReader {
        Self {
            urls: urls.to_owned(),
            tries,
            client: Client::new(),
        }
    }

    pub fn new_from_key(
        key: &str,
        io_hosts: &Vec<&str>,
        ak: &str,
        sk: &str,
        uid: u64,
        bucket: &str,
        sim: bool,
        private: bool,
    ) -> RangeReader {
        let credential = Credential::new(ak, sk);
        let urls = io_hosts
            .iter()
            .map(|host| {
                let url = if uid == 0 || sim {
                    format!("{}{}", host, key)
                } else {
                    format!("{}/getfile/{}/{}{}", host, uid, bucket, key)
                };
                if private {
                    return sign_download_url_with_lifetime(
                        &credential,
                        Url::parse(&url).unwrap(),
                        Duration::from_secs(3600 * 24),
                        false,
                    ).unwrap();
                }
                return url;
            })
            .collect::<Vec<_>>();
        Self::new(&urls, 5)
    }
    fn read_at_internal(&self, pos: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut ret: Option<std::io::Result<usize>> = None;
        let size = buf.len() as u64;
        let range = format!("bytes={}-{}", pos, pos + size - 1);
        trace!("read_at_internal {}", &range);
        let mut u:&str = "";
        for url in self.choose_urls() {
            let x = self.client.get(url)
                .header("Range", &range).header("User-Agent", UA).send();
            match x {
                Err(e) => {
                    let e2 = Error::new(ErrorKind::ConnectionAborted, e.to_string());
                    ret = Some(Err(e2));
                }
                Ok(resp) => {
                    let code = resp.status();
                    if code != 206 {
                        let e = Error::new(ErrorKind::InvalidData, code.as_str());
                        if code.as_u16() / 100 == 4 {
                            return Err(e);
                        }
                        ret = Some(Err(e));
                        continue;
                    }
                    let data = resp.bytes();
                    match data {
                        Err(e) => {
                            let e2 = Error::new(ErrorKind::ConnectionAborted, e.to_string());
                            ret = Some(Err(e2));
                        }
                        Ok(b) => {
                            buf.copy_from_slice(b.as_ref());
                            return Ok(b.len());
                        }
                    }
                }
            }
        }
        warn!("final failed read at internal {} {:?}", u, ret);
        return ret.unwrap();
    }

    pub fn read_last_bytes(&self, length: usize) -> std::io::Result<(u64, Vec<u8>)> {
        let range = format!("bytes=-{}", length);
        let mut ret: Option<std::io::Result<(u64, Vec<u8>)>> = None;
        let timestamp = SystemTime::now();
        let mut retry_index = 0;
        let mut u:&str = "";
        for url in self.choose_urls() {
            if retry_index == 3 {
                thread::sleep(Duration::from_secs(5));
            } else if retry_index == 4 {
                thread::sleep(Duration::from_secs(15));
            }
            retry_index+=1;
            u = url;
            let x = self.client.get(url)
                .header("Range", &range).header("User-Agent", UA).send();
            match x {
                Err(e) => {
                    warn!("error is {} {}", url, e);
                    let e2 = Error::new(ErrorKind::ConnectionAborted, e.to_string());
                    ret = Some(Err(e2));
                }
                Ok(mut resp) => {
                    let code = resp.status();
                    let content_length = resp.content_length();
                    let content_range = resp.headers().get("Content-Range");
                    debug!(
                        "code is {}, {:?} {:?} len {} time {:?}",
                        code, content_range, content_length, length, timestamp.elapsed()
                    );
                    if code != 206 {
                        let e = Error::new(ErrorKind::InvalidData, code.as_str());
                        if code.as_u16() < 500 {
                            warn!("code is {} {}", url, e);
                            return Err(e);
                        } else {
                            ret = Some(Err(e));
                            continue;
                        }
                    }
                    if content_length.is_none() {
                        let e = Error::new(ErrorKind::InvalidData, "no content length");
                        warn!("no content length {}", url);
                        ret = Some(Err(e));
                        continue;
                    }
                    let content_length = content_length.unwrap();
                    // debug!("check code {}, {:?}", code, content_range);
                    if content_range.is_none() {
                        let e = Error::new(ErrorKind::InvalidData, "no content range");
                        warn!("no content range {}", url);
                        ret = Some(Err(e));
                        continue;
                    }
                    let cr = content_range.unwrap().to_str().unwrap();
                    let r1: Vec<&str> = cr.split("/").collect();
                    if r1.len() != 2 {
                        let e = Error::new(ErrorKind::InvalidData, cr);
                        warn!("invalid content range {} {}", url, cr);
                        ret = Some(Err(e));
                        continue;
                    }
                    let file_length = r1[1].parse::<u64>();
                    if file_length.is_err() {
                        let e = Error::new(ErrorKind::InvalidData, cr);
                        warn!("invalid content range parse{} {}", url, cr);
                        ret = Some(Err(e));
                        continue;
                    }
                    let file_length = file_length.unwrap();
                    let mut bytes = Vec::with_capacity(length);
                    let n = resp.read_to_end(&mut bytes);

                    if n.is_ok() {
                        info!("download url {}, hash {}", url, data_hash(&bytes));
                        let n = n.unwrap();
                        if n != content_length as usize || n == 0{
                            let e = Error::new(ErrorKind::InvalidData, "no content length");
                            warn!("invalid content length {} {} {}", url, n, content_length);
                            ret = Some(Err(e));
                            continue;
                        }
                        return Ok((file_length, bytes));
                    } else {
                        let e = n.err().unwrap();
                        warn!("download url read to end error {} {}", url, e);
                        ret = Some(Err(e));
                    }
                }
            }
        }
        warn!("final failed read_last_bytes {} {:?}", u, ret);
        return ret.unwrap();
    }

    pub fn read_multi_range(
        &self,
        buf: &mut [u8],
        ranges: &Vec<(u64, u64)>,
        pos_list: &mut Vec<(u64, u64)>,
    ) -> std::io::Result<usize> {
        let mut ret: Option<std::io::Result<usize>> = None;
        debug!("download multi range {} {}", buf.len(), ranges.len());
        let range = format!("bytes={}", gen_range(ranges));
        let timestamp = SystemTime::now();
        let mut retry_index = 0;
        let mut u:&str = "";
        for url in self.choose_urls() {
            if retry_index == 3 {
                thread::sleep(Duration::from_secs(5));
            } else if retry_index == 4 {
                thread::sleep(Duration::from_secs(15));
            }
            retry_index+=1;
            u = url;
            pos_list.clear();
            debug!("download multi range {} {}",url, &range);
            let x = self.client.get(url)
                .header("Range", &range).header("User-Agent", UA).send();
            match x {
                Err(e) => {
                    let e2 = Error::new(ErrorKind::ConnectionAborted, e.to_string());
                    debug!("error is {}", e);
                    ret = Some(Err(e2));
                }
                Ok(mut resp) => {
                    let code = resp.status();
                    debug!("code is {}", code);
                    // any range equals length
                    if code == 200 {
                        let ct_len = resp.content_length();
                        if ct_len.is_none() {
                            warn!("download content length is none {}", url);
                            let et = Error::new(ErrorKind::InvalidInput, "no content length");
                            return Err(et);
                        }
                        let b = resp.bytes().unwrap();
                        let l = ct_len.unwrap() as usize;
                        let mut pos = 0;
                        for (i, j) in ranges {
                            let i1 = *i as usize;
                            let j1 = *j as usize;
                            if pos + j1 > buf.len() || i1 + j1 > l {
                                warn!(
                                    "data out of range{} {} {} {} {}",
                                    url,
                                    pos + j1,
                                    buf.len(),
                                    i1 + j1,
                                    l
                                );
                                let et = Error::new(ErrorKind::InvalidInput, "data out of range");
                                return Err(et);
                            }
                            pos_list.push(((*i) << 24 | (*j), pos as u64));
                            buf[pos..(pos + j1)].copy_from_slice(&b.slice(i1..(i1 + j1)));
                            trace!("200 copy {} {} {}", i, j, pos);
                            pos += j1;
                        }
                        info!("download {} hash {}", url, data_hash(buf));
                        return Ok(buf.len());
                    }

                    if code != 206 {
                        let e = Error::new(ErrorKind::InvalidData, code.as_str());
                        if code.as_u16() / 100 == 4 {
                            warn!("meet error {} code {}", url, code);
                            return Err(e);
                        }
                        ret = Some(Err(e));
                        continue;
                    }
                    let c_len = resp.content_length();
                    if c_len.is_none() {
                        warn!("content length is none {}", url);
                        let et = Error::new(ErrorKind::InvalidData, "no content length");
                        ret = Some(Err(et));
                        continue;
                    }
                    let ct = resp.headers().get("Content-Type");
                    if ct.is_none() {
                        warn!("content is none {}", url);
                        let et = Error::new(ErrorKind::InvalidData, "no content type");
                        ret = Some(Err(et));
                        continue;
                    }
                    let ct = ct.unwrap().to_str().unwrap();
                    trace!("content is {}", ct);
                    let boundary = boundary_str(ct);
                    if boundary.is_none() {
                        warn!("boundary is none {}", url);
                        let et = Error::new(ErrorKind::InvalidData, "no boundary");
                        ret = Some(Err(et));
                        continue;
                    }
                    trace!("boundary is {:?}", boundary);
                    let ct = ct.to_string();
                    let size = c_len.unwrap();
                    let mut off: usize = 0;
                    let mut bytes = Vec::with_capacity(size as usize);
                    let r = resp.read_to_end(&mut bytes);
                    if r.is_err() {
                        warn!("read body error {} {:?}", url, r.err());
                        let et = Error::new(ErrorKind::InvalidData, "read body error");
                        ret = Some(Err(et));
                        continue;
                    }

                    let buf_body = Cursor::new(&bytes);
                    let mut multipart = Multipart::with_body(buf_body, boundary.unwrap());
                    let mut index = 0;

                    let data = multipart.foreach_entry(|mut field| {
                        let range = field.headers.range;
                        trace!(
                            "multi range {:?} type {:?}",
                            range,
                            field.headers.content_type
                        );
                        let mut l = 0;
                        if range.is_none() {
                            warn!("no range header {}", url);
                            return;
                        }
                        let range_str = range.unwrap();
                        let range = parse_range(&range_str);
                        if range.is_err() {
                            warn!("invalid range header {} {:?}", url, range.err());
                            return;
                        }
                        let (start, length) = range.unwrap();
                        loop {
                            let n = field.data.read(&mut buf[off..]);
                            if n.is_err() {
                                let et = n.err().unwrap();
                                warn!("read range {} error {:?}", url, et);
                                ret = Some(Err(et));
                                break;
                            }

                            let x = n.unwrap();
                            if x == 0 {
                                break;
                            }
                            l += x;
                            off+=x;
                        }
                        debug!(
                            "multi range size--- {} {} {} {}",
                            l,
                            off,
                            buf[off - l],
                            buf[off - 1]
                        );
                        if l as u64 != length {
                            warn!("data length not equal {} {} {} {} {}", url, range_str, l, start, length);
                            fs::write(file_name(url), &bytes);
                            return;
                        }
                        let r1 = ranges.get(index);
                        if r1.is_none() {
                            warn!("data range out request {} {} {} {} {}", url, range_str, l, start, length);
                            fs::write(file_name(url), &bytes);
                            return;
                        }
                        pos_list.push((start << 24 | l as u64, (off-l) as u64));
                        let (start1, l1) = r1.unwrap();
                        if *start1 != start || *l1 != length as u64{
                            warn!("data range order mismatch {} {} {} {} {} {}", url, range_str, start1, l1, start, length);
                            fs::write(file_name(url), &bytes);
                            return;
                        }
                        index+=1;
                    });
                    match data {
                        Err(e) => {
                            warn!("result meet error {} {} {}", url, ct, e);
                            let e2 = Error::new(ErrorKind::Interrupted, e.to_string());
                            ret = Some(Err(e2));
                        }
                        Ok(_b) => {
                            if off != buf.len() || pos_list.len() != ranges.len(){
                                warn!("return data mismatch {} {} {} {} ranges {} {}", url, ct, off,
                                      buf.len(), pos_list.len(), ranges.len());
                                let et = Error::new(ErrorKind::Interrupted, "data mis match");
                                ret = Some(Err(et));
                            } else {
                                debug!("down ok {} {:?}", url,  timestamp.elapsed());
                                info!("download {}, hash {}", url, data_hash(buf));
                                return Ok(buf.len());
                            }
                        }
                    }
                }
            }
        }
        warn!("final failed read multi range {} {:?}", u, ret);
        return ret.unwrap();
    }

    pub fn exist(&self) -> std::io::Result<bool> {
        let mut ret: Option<std::io::Result<bool>> = None;
        for url in self.choose_urls() {
            let x = self.client.head(url).header("User-Agent", UA).send();
            match x {
                Err(e) => {
                    let e2 = Error::new(ErrorKind::ConnectionAborted, e.to_string());
                    ret = Some(Err(e2));
                }
                Ok(resp) => {
                    let code = resp.status();
                    if code == 200 {
                        return Ok(true);
                    } else if code == 404 {
                        return Ok(false);
                    } else {
                        let e = Error::new(ErrorKind::BrokenPipe, code.as_str());
                        ret = Some(Err(e));
                    }
                }
            }
        }
        return ret.unwrap();
    }

    pub fn download(&self, file: &mut std::fs::File) -> std::io::Result<u64> {
        let mut ret: Option<std::io::Result<u64>> = None;
        for url in self.choose_urls() {
            let x = self.client.get(url).header("User-Agent", UA).send();
            match x {
                Err(e) => {
                    let e2 = Error::new(ErrorKind::ConnectionAborted, e.to_string());
                    ret = Some(Err(e2));
                }
                Ok(mut resp) => {
                    let code = resp.status();
                    debug!("code is {}", code);
                    if code != 200 {
                        let e = Error::new(ErrorKind::InvalidData, code.as_str());
                        if code.as_u16() / 100 == 4 {
                            return Err(e);
                        }
                        ret = Some(Err(e));
                        continue;
                    }
                    debug!("content length is {:?}", resp.content_length());
                    let n = resp.copy_to(file);
                    if n.is_err() {
                        let e1 = n.err();
                        info!("download error {:?}", e1);
                        let e = Error::new(ErrorKind::BrokenPipe, e1.unwrap().to_string());
                        ret = Some(Err(e));
                        continue;
                    }
                    return Ok(n.unwrap());
                }
            }
        }
        return ret.unwrap();
    }

    pub fn download_bytes(&self) -> std::io::Result<Vec<u8>> {
        let mut ret: Option<std::io::Result<Vec<u8>>> = None;
        let timestamp = SystemTime::now();
        let mut retry_index = 0;
        let mut u:&str = "";
        for url in self.choose_urls() {
            if retry_index == 3 {
                thread::sleep(Duration::from_secs(5));
            } else if retry_index == 4 {
                thread::sleep(Duration::from_secs(15));
            }
            retry_index+=1;
            u = url;
            let x = self.client.get(url).header("User-Agent", UA).send();
            match x {
                Err(e) => {
                    let e2 = Error::new(ErrorKind::ConnectionAborted, e.to_string());
                    ret = Some(Err(e2));
                    warn!("download error {} {}", url, e);
                }
                Ok(mut resp) => {
                    let code = resp.status();
                    debug!("code is {}", code);
                    if code != 200 {
                        let e = Error::new(ErrorKind::InvalidData, code.as_str());
                        if code.as_u16() / 100 == 4 {
                            warn!("download error {} {}", url, e);
                            return Err(e);
                        }
                        ret = Some(Err(e));
                        continue;
                    }

                    let mut size = 64 * 1024;
                    let l = resp.content_length();
                    if l.is_some() {
                        debug!("content length is {:?}", l);
                        size = l.unwrap();
                    }
                    if l.is_none() {
                        warn!("no content length {}", url);
                        let et = Error::new(ErrorKind::InvalidData, "no content length");
                        ret = Some(Err(et));
                        continue;
                    }
                    let mut bytes = Vec::with_capacity(size as usize);
                    let r = resp.read_to_end(&mut bytes);
                    debug!("download size is {:?}, {}, time {:?}", r, bytes.len(), timestamp.elapsed());
                    if r.is_err()  {
                        let et = r.err().unwrap();
                        warn!("download len not equal {} {} {}", url,  bytes.len(), et);
                        ret = Some(Err(et));
                        continue;
                    }
                    let t = r.unwrap();
                    if t != bytes.len() {
                        warn!("download len not equal {} {} {}", url,  bytes.len(), t);
                        let e2 = Error::new(ErrorKind::Interrupted, "read length not equal");
                        ret = Some(Err(e2));
                        continue;
                    }
                    if t as u64 != size  || t == 0 {
                        warn!("download len not equal ct-len {} {} {}", url,  size, t);
                        let e2 = Error::new(ErrorKind::Interrupted, "read length not equal");
                        ret = Some(Err(e2));
                        continue;
                    }
                    // if is_debug() {
                        info!("download {} hash {}", url, data_hash(&bytes));
                    // }
                    return Ok(bytes);
                }
            }
        }
        warn!("final failed download_bytes {} {:?}", u, ret);
        return ret.unwrap();
    }

    fn choose_urls(&self) -> Vec<&str> {
        let mut urls: Vec<&str> = self
            .urls
            .choose_multiple(&mut thread_rng(), self.tries)
            .map(|s| s.as_str())
            .collect();
        if urls.len() < self.tries {
            let still_needed = self.tries - urls.len();
            for i in 0..still_needed {
                let index = i % self.urls.len();
                urls.push(urls[index]);
            }
        }
        urls
    }
}

impl Read for RangeReader {
    //dummy
    fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        debug!("range reader read dummy");
        Ok(0)
    }
}

impl ReadAt for RangeReader {
    fn read_at(&self, pos: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let r = self.read_at_internal(pos, buf);
        match r {
            Ok(size) => Ok(size),
            Err(e) => Err(Error::new(ErrorKind::Other, e)),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct Config {
    ak: String,
    sk: String,
    bucket: String,
    io_hosts: Vec<String>,
    uid: u64,
    sim: bool,
    private: Option<bool>,
}

#[derive(Deserialize, Debug)]
pub struct TempDirInfo {
    pub weight: Option<u64>,
}

static qiniu_conf: Lazy<Option<Config>> = Lazy::new(load_conf);

pub fn qiniu_is_enable() -> bool {
    qiniu_conf.is_some()
}

fn load_conf() -> Option<Config> {
    let x = env::var("QINIU");
    if x.is_err() {
        info!("QINIU Env IS NOT ENABLE");
        return None;
    }
    let conf_path = x.unwrap();
    let v = std::fs::read(&conf_path);
    if v.is_err() {
        warn!("config file is not exist {}", &conf_path);
        return None;
    }
    let conf: Config = if conf_path.ends_with(".toml"){
        toml::from_slice(&v.unwrap()).unwrap()
    } else {
        serde_json::from_slice(&v.unwrap()).unwrap()
    };
    return Some(conf);
}

pub fn reader_from_config(path: &str, conf: &Config) -> Option<RangeReader> {
    let hosts = Vec::from_iter(conf.io_hosts.iter().map(String::as_str));
    let private = conf.private.unwrap_or(false);
    let r = RangeReader::new_from_key(
        path,
        &hosts,
        &conf.ak,
        &conf.sk,
        conf.uid,
        &conf.bucket,
        conf.sim,
        private,
    );
    Some(r)
}

pub fn reader_from_env(path: &str) -> Option<RangeReader> {
    if !qiniu_is_enable() {
        return None;
    }
    return reader_from_config(path, qiniu_conf.as_ref().unwrap());
}

pub fn read_batch(path: &str, buf: &mut [u8], ranges: &Vec<(u64, u64)>, pos_list: &mut Vec<(u64, u64)>) -> std::io::Result<usize> {
    let q = reader_from_env(path);
    if q.is_some() && ranges.len() != 0 {
        return q.unwrap().read_multi_range(buf, ranges, pos_list);
    }
    let e2 = Error::new(ErrorKind::AddrNotAvailable, "no qiniu env");
    return Err(e2);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{error::Error, result::Result};
    static path:&str = "/Users/long/projects/filecoin/lotus/stdir/bench832045109/cache/s-t01000-1/t_aux";
    #[test]
    fn test_last_bytes_down_ok() {
        let io_hosts = vec!["http://127.0.0.1:10800"];
        let reader = RangeReader::new_from_key(path, &io_hosts, "123", "456",
                                               0, "test", true, false);
        let ret = reader.read_last_bytes(32);
        assert!(ret.is_ok());
        let r = ret.unwrap();
        assert_eq!(r.0, 575);
        let v = r.1;
        println!("{} {} {} {}", v[0], v[1], v[v.len()-2], v[v.len()-1]);
    }

    #[test]
    fn test_last_bytes_down_error() {
        let io_hosts = vec!["http://127.0.0.1:10802"];
        let reader = RangeReader::new_from_key(path, &io_hosts, "123", "456",
                                               0, "test", true, false);
        let ret = reader.read_last_bytes(32);
        assert!(ret.is_err());
    }

    #[test]
    fn test_last_bytes_down_5xx() {
        let io_hosts = vec!["http://127.0.0.1:10801/500"];
        let reader = RangeReader::new_from_key(path, &io_hosts, "123", "456",
                                               0, "test", true, false);
        let ret = reader.read_last_bytes(32);
        assert!(ret.is_err());
    }

    #[test]
    fn test_last_bytes_down_retry() {
        let io_hosts = vec!["http://127.0.0.1:10801/599", "http://127.0.0.1:10801/206", "http://127.0.0.1:10802",
                            "http://127.0.0.1:10800"];
        let reader = RangeReader::new_from_key(path, &io_hosts, "123", "456",
                                               0, "test", true, false);
        let ret = reader.read_last_bytes(32).unwrap();
        let length = ret.0;
        let buffer = ret.1;
        println!("{} {} {} {}", buffer[0], buffer[1], buffer[buffer.len()-2], buffer[buffer.len()-1]);
        assert_eq!(length, 575);
    }

    #[test]
    fn test_multi_down_ok() {
        let io_hosts = vec!["http://127.0.0.1:10800"];
        let reader = RangeReader::new_from_key(path, &io_hosts, "123", "456",
                                               0, "test", true, false);
        let mut read_data = vec![0; 2+6];
        let range = vec![(16,2), (32,6)];
        let mut pos:Vec<(u64, u64)> = Vec::with_capacity(range.len());
        let ret = reader.read_multi_range(&mut read_data, &range, &mut pos);
        let r = ret.unwrap();
        assert_eq!(r, 2+6);
        let v = read_data;
        println!("{} {} {} {}", v[0], v[1], v[v.len()-2], v[v.len()-1]);
    }

    #[test]
    fn test_multi_down_error() {
        let io_hosts = vec!["http://127.0.0.1:10802"];
        let reader = RangeReader::new_from_key(path, &io_hosts, "123", "456",
                                               0, "test", true, false);
        let mut read_data = vec![0; 2+6];
        let range = vec![(16,2), (32,6)];
        let mut pos:Vec<(u64, u64)> = Vec::with_capacity(range.len());
        let ret = reader.read_multi_range(&mut read_data, &range, &mut pos);
        assert!(ret.is_err());
    }

    #[test]
    fn test_multi_down_5xx() {
        let io_hosts = vec!["http://127.0.0.1:10801/500"];
        let reader = RangeReader::new_from_key(path, &io_hosts, "123", "456",
                                               0, "test", true, false);
        let mut read_data = vec![0; 2+6];
        let range = vec![(16,2), (32,6)];
        let mut pos:Vec<(u64, u64)> = Vec::with_capacity(range.len());
        let ret = reader.read_multi_range(&mut read_data, &range, &mut pos);
        assert!(ret.is_err());
    }

    #[test]
    fn test_multi_down_retry() {
        let io_hosts = vec!["http://127.0.0.1:10801/599", "http://127.0.0.1:10801/206", "http://127.0.0.1:10802",
                            "http://127.0.0.1:10800"];
        let reader = RangeReader::new_from_key(path, &io_hosts, "123", "456",
                                               0, "test", true, false);
        let mut read_data = vec![0; 2+6+4];
        let range = vec![(16,2), (32,6), (52,4)];
        let mut pos:Vec<(u64, u64)> = Vec::with_capacity(range.len());
        let ret = reader.read_multi_range(&mut read_data, &range, &mut pos);
        let buffer = read_data;
        println!("{} {} {} {} {}", buffer[0], buffer[1], buffer[buffer.len()-2], buffer[buffer.len()-1], data_hash(&buffer));
        assert_eq!(ret.unwrap(), 2+6+4);
    }

    #[test]
    fn test_bytes_down_ok() {
        let io_hosts = vec!["http://127.0.0.1:10800"];
        let reader = RangeReader::new_from_key(path, &io_hosts, "123", "456",
                                               0, "test", true, false);
        let ret = reader.download_bytes();
        assert!(ret.is_ok());
        let v = ret.unwrap();
        assert_eq!(v.len(), 575);
        println!("{} {} {} {}", v[0], v[1], v[v.len()-2], v[v.len()-1]);
    }

    #[test]
    fn test_bytes_down_error() {
        let io_hosts = vec!["http://127.0.0.1:10802"];
        let reader = RangeReader::new_from_key(path, &io_hosts, "123", "456",
                                               0, "test", true, false);
        let ret = reader.download_bytes();
        assert!(ret.is_err());
    }

    #[test]
    fn test_bytes_down_5xx() {
        let io_hosts = vec!["http://127.0.0.1:10801/500"];
        let reader = RangeReader::new_from_key(path, &io_hosts, "123", "456",
                                               0, "test", true, false);
        let ret = reader.download_bytes();
        assert!(ret.is_err());
    }

    #[test]
    fn test_bytes_down_retry() {
        let io_hosts = vec!["http://127.0.0.1:10801/500", "http://127.0.0.1:10801/200", "http://127.0.0.1:10802",
                            "http://127.0.0.1:10800"];
        let reader = RangeReader::new_from_key(path, &io_hosts, "123", "456",
                                               0, "test", true, false);
        let ret = reader.download_bytes().unwrap();
        assert_eq!(ret.len(), 575);
        let buffer = ret;
        println!("{} {} {} {}", buffer[0], buffer[1], buffer[buffer.len()-2], buffer[buffer.len()-1]);
    }

    fn parse_range(s: &str) ->(u64, Vec<(u64, u64)>) {
        let ss:Vec<&str> = s.split(",").collect();
        let mut range:Vec<(u64, u64)> = Vec::with_capacity(ss.len());
        let mut l:u64 = 0;
        for sv in ss {
            let s2:Vec<&str> = sv.split("-").collect();
            let start = s2[0].parse::<u64>().unwrap();
            let end = s2[1].parse::<u64>().unwrap();
            let len = end-start +1;
            l += len;
            range.push((start, len));
        }
        return (l, range);
    }

    #[test]
    fn test_multi_repeat() {
        let io_hosts = vec!["http://172.17.210.8:5000/getfile/5/t023530"];
        let reader = RangeReader::new_from_key("/home/ipfsunion/.dfs/sealed/s-t023530-171493", &io_hosts, "123", "456",
                                               0, "test", true, false);
        let x = "10716184576-10716200959,10716199488-10716199519,10716199424-10716199455,10716199456-10716199487,10716199520-10716199551,10716199552-10716199583,10716199584-10716199615,10716199616-10716199647,10716199648-10716199679,8428617728-8428634111,8428629728-8428629759,8428629504-8428629535,8428629536-8428629567,8428629568-8428629599,8428629600-8428629631,8428629632-8428629663,8428629664-8428629695,8428629696-8428629727,891174912-891191295,891185152-891185183,891185184-891185215,891185216-891185247,891185248-891185279,891185280-891185311,891185312-891185343,891185344-891185375,891185376-891185407,23235493888-23235510271,23235499200-23235499231,23235499008-23235499039,23235499040-23235499071,23235499072-23235499103,23235499104-23235499135,23235499136-23235499167,23235499168-23235499199,23235499232-23235499263,15718498304-15718514687,15718509632-15718509663,15718509568-15718509599,15718509600-15718509631,15718509664-15718509695,15718509696-15718509727,15718509728-15718509759,15718509760-15718509791,15718509792-15718509823,17104224256-17104240639,17104228032-17104228063,17104227840-17104227871,17104227872-17104227903,17104227904-17104227935,17104227936-17104227967,17104227968-17104227999,17104228000-17104228031,17104228064-17104228095,4041408512-4041424895,4041410272-4041410303,4041410048-4041410079,4041410080-4041410111,4041410112-4041410143,4041410144-4041410175,4041410176-4041410207,4041410208-4041410239,4041410240-4041410271,21063565312-21063581695,21063566400-21063566431,21063566336-21063566367,21063566368-21063566399,21063566432-21063566463,21063566464-21063566495,21063566496-21063566527,21063566528-21063566559,21063566560-21063566591,22083649536-22083665919,22083658560-22083658591,22083658496-22083658527,22083658528-22083658559,22083658592-22083658623,22083658624-22083658655,22083658656-22083658687,22083658688-22083658719,22083658720-22083658751,21187182592-21187198975,21187188640-21187188671,21187188480-21187188511,21187188512-21187188543,21187188544-21187188575,21187188576-21187188607,21187188608-21187188639,21187188672-21187188703,21187188704-21187188735,31598247936-31598264319,31598261920-31598261951,31598261760-31598261791,31598261792-31598261823,31598261824-31598261855,31598261856-31598261887,31598261888-31598261919,31598261952-31598261983,31598261984-31598262015,31935987712-31936004095,31936001728-31936001759,31936001536-31936001567,31936001568-31936001599,31936001600-31936001631,31936001632-31936001663,31936001664-31936001695,31936001696-31936001727,31936001760-31936001791,21436186624-21436203007,21436197024-21436197055,21436196864-21436196895,21436196896-21436196927,21436196928-21436196959,21436196960-21436196991,21436196992-21436197023,21436197056-21436197087,21436197088-21436197119,10721624064-10721640447,10721628352-10721628383,10721628160-10721628191,10721628192-10721628223,10721628224-10721628255,10721628256-10721628287,10721628288-10721628319,10721628320-10721628351,10721628384-10721628415,18109267968-18109284351,18109271808-18109271839,18109271840-18109271871,18109271872-18109271903,18109271904-18109271935,18109271936-18109271967,18109271968-18109271999,18109272000-18109272031,18109272032-18109272063,32366624768-32366641151,32366630688-32366630719,32366630656-32366630687,32366630720-32366630751,32366630752-32366630783,32366630784-32366630815,32366630816-32366630847,32366630848-32366630879,32366630880-32366630911,22593994752-22594011135,22594004672-22594004703,22594004480-22594004511,22594004512-22594004543,22594004544-22594004575,22594004576-22594004607,22594004608-22594004639,22594004640-22594004671,22594004704-22594004735,25736019968-25736036351,25736022784-25736022815,25736022816-25736022847,25736022848-25736022879,25736022880-25736022911,25736022912-25736022943,25736022944-25736022975,25736022976-25736023007,25736023008-25736023039,29424205824-29424222207,29424217472-29424217503,29424217344-29424217375,29424217376-29424217407,29424217408-29424217439,29424217440-29424217471,29424217504-29424217535,29424217536-29424217567,29424217568-29424217599,8157921280-8157937663,8157924096-8157924127,8157924128-8157924159,8157924160-8157924191,8157924192-8157924223,8157924224-8157924255,8157924256-8157924287,8157924288-8157924319,8157924320-8157924351,25688866816-25688883199,25688868512-25688868543,25688868352-25688868383,25688868384-25688868415,25688868416-25688868447,25688868448-25688868479,25688868480-25688868511,25688868544-25688868575,25688868576-25688868607,18980061184-18980077567,18980075616-18980075647,18980075520-18980075551,18980075552-18980075583,18980075584-18980075615,18980075648-18980075679,18980075680-18980075711,18980075712-18980075743,18980075744-18980075775,30602428416-30602444799,30602429472-30602429503,30602429440-30602429471,30602429504-30602429535,30602429536-30602429567,30602429568-30602429599,30602429600-30602429631,30602429632-30602429663,30602429664-30602429695,6557581312-6557597695,6557583040-6557583071,6557582848-6557582879,6557582880-6557582911,6557582912-6557582943,6557582944-6557582975,6557582976-6557583007,6557583008-6557583039,6557583072-6557583103,13809483776-13809500159,13809496960-13809496991,13809496832-13809496863,13809496864-13809496895,13809496896-13809496927,13809496928-13809496959,13809496992-13809497023,13809497024-13809497055,13809497056-13809497087,12372623360-12372639743,12372625952-12372625983,12372625920-12372625951,12372625984-12372626015,12372626016-12372626047,12372626048-12372626079,12372626080-12372626111,12372626112-12372626143,12372626144-12372626175,24545411072-24545427455,24545425664-24545425695,24545425696-24545425727,24545425728-24545425759,24545425760-24545425791,24545425792-24545425823,24545425824-24545425855,24545425856-24545425887,24545425888-24545425919,17451220992-17451237375,17451232064-17451232095,17451232000-17451232031,17451232032-17451232063,17451232096-17451232127,17451232128-17451232159,17451232160-17451232191,17451232192-17451232223,17451232224-17451232255,27410235392-27410251775,27410237120-27410237151,27410236928-27410236959,27410236960-27410236991,27410236992-27410237023,27410237024-27410237055,27410237056-27410237087,27410237088-27410237119,27410237152-27410237183,19052691456-19052707839,19052692864-19052692895,19052692736-19052692767,19052692768-19052692799,19052692800-19052692831,19052692832-19052692863,19052692896-19052692927,19052692928-19052692959,19052692960-19052692991,23341285376-23341301759,23341299712-23341299743,23341299744-23341299775,23341299776-23341299807,23341299808-23341299839,23341299840-23341299871,23341299872-23341299903,23341299904-23341299935,23341299936-23341299967,23465082880-23465099263,23465083616-23465083647,23465083392-23465083423,23465083424-23465083455,23465083456-23465083487,23465083488-23465083519,23465083520-23465083551,23465083552-23465083583,23465083584-23465083615,27266580480-27266596863,27266589056-27266589087,27266588928-27266588959,27266588960-27266588991,27266588992-27266589023,27266589024-27266589055,27266589088-27266589119,27266589120-27266589151,27266589152-27266589183,12175605760-12175622143,12175609152-12175609183,12175609088-12175609119,12175609120-12175609151,12175609184-12175609215,12175609216-12175609247,12175609248-12175609279,12175609280-12175609311,12175609312-12175609343,20065599488-20065615871,20065600704-20065600735,20065600512-20065600543,20065600544-20065600575,20065600576-20065600607,20065600608-20065600639,20065600640-20065600671,20065600672-20065600703,20065600736-20065600767,8810561536-8810577919,8810564256-8810564287,8810564096-8810564127,8810564128-8810564159,8810564160-8810564191,8810564192-8810564223,8810564224-8810564255,8810564288-8810564319,8810564320-8810564351,23132487680-23132504063,23132494912-23132494943,23132494848-23132494879,23132494880-23132494911,23132494944-23132494975,23132494976-23132495007,23132495008-23132495039,23132495040-23132495071,23132495072-23132495103,30148575232-30148591615,30148587232-30148587263,30148587008-30148587039,30148587040-30148587071,30148587072-30148587103,30148587104-30148587135,30148587136-30148587167,30148587168-30148587199,30148587200-30148587231,17881366528-17881382911,17881379328-17881379359,17881379360-17881379391,17881379392-17881379423,17881379424-17881379455,17881379456-17881379487,17881379488-17881379519,17881379520-17881379551,17881379552-17881379583,1378779136-1378795519,1378781408-1378781439,1378781184-1378781215,1378781216-1378781247,1378781248-1378781279,1378781280-1378781311,1378781312-1378781343,1378781344-1378781375,1378781376-1378781407,10276634624-10276651007,10276641440-10276641471,10276641280-10276641311,10276641312-10276641343,10276641344-10276641375,10276641376-10276641407,10276641408-10276641439,10276641472-10276641503,10276641504-10276641535,9912401920-9912418303,9912411136-9912411167,9912411168-9912411199,9912411200-9912411231,9912411232-9912411263,9912411264-9912411295,9912411296-9912411327,9912411328-9912411359,9912411360-9912411391,25992003584-25992019967,25992011168-25992011199,25992011008-25992011039,25992011040-25992011071,25992011072-25992011103,25992011104-25992011135,25992011136-25992011167,25992011200-25992011231,25992011232-25992011263,33002749952-33002766335,33002759040-33002759071,33002758912-33002758943,33002758944-33002758975,33002758976-33002759007,33002759008-33002759039,33002759072-33002759103,33002759104-33002759135,33002759136-33002759167,24977211392-24977227775,24977224128-24977224159,24977223936-24977223967,24977223968-24977223999,24977224000-24977224031,24977224032-24977224063,24977224064-24977224095,24977224096-24977224127,24977224160-24977224191,16853155840-16853172223,16853160352-16853160383,16853160192-16853160223,16853160224-16853160255,16853160256-16853160287,16853160288-16853160319,16853160320-16853160351,16853160384-16853160415,16853160416-16853160447,29523984384-29524000767,29523994432-29523994463,29523994368-29523994399,29523994400-29523994431,29523994464-29523994495,29523994496-29523994527,29523994528-29523994559,29523994560-29523994591,29523994592-29523994623,28411363328-28411379711,28411371840-28411371871,28411371776-28411371807,28411371808-28411371839,28411371872-28411371903,28411371904-28411371935,28411371936-28411371967,28411371968-28411371999,28411372000-28411372031,33154646016-33154662399,33154661760-33154661791,33154661632-33154661663,33154661664-33154661695,33154661696-33154661727,33154661728-33154661759,33154661792-33154661823,33154661824-33154661855,33154661856-33154661887,16025485312-16025501695,16025495520-16025495551,16025495296-16025495327,16025495328-16025495359,16025495360-16025495391,16025495392-16025495423,16025495424-16025495455,16025495456-16025495487,16025495488-16025495519,24698388480-24698404863,24698389216-24698389247,24698388992-24698389023,24698389024-24698389055,24698389056-24698389087,24698389088-24698389119,24698389120-24698389151,24698389152-24698389183,24698389184-24698389215,30337318912-30337335295,30337323296-30337323327,30337323264-30337323295,30337323328-30337323359,30337323360-30337323391,30337323392-30337323423,30337323424-30337323455,30337323456-30337323487,30337323488-30337323519,16172662784-16172679167,16172678784-16172678815,16172678656-16172678687,16172678688-16172678719,16172678720-16172678751,16172678752-16172678783,16172678816-16172678847,16172678848-16172678879,16172678880-16172678911,11120738304-11120754687,11120745760-11120745791,11120745728-11120745759,11120745792-11120745823,11120745824-11120745855,11120745856-11120745887,11120745888-11120745919,11120745920-11120745951,11120745952-11120745983,11856723968-11856740351,11856724096-11856724127,11856723968-11856723999,11856724000-11856724031,11856724032-11856724063,11856724064-11856724095,11856724128-11856724159,11856724160-11856724191,11856724192-11856724223,22645784576-22645800959,22645799104-22645799135,22645798912-22645798943,22645798944-22645798975,22645798976-22645799007,22645799008-22645799039,22645799040-22645799071,22645799072-22645799103,22645799136-22645799167,16850567168-16850583551,16850578816-16850578847,16850578688-16850578719,16850578720-16850578751,16850578752-16850578783,16850578784-16850578815,16850578848-16850578879,16850578880-16850578911,16850578912-16850578943,12863733760-12863750143,12863741760-12863741791,12863741696-12863741727,12863741728-12863741759,12863741792-12863741823,12863741824-12863741855,12863741856-12863741887,12863741888-12863741919,12863741920-12863741951,25563955200-25563971583,25563960384-25563960415,25563960320-25563960351,25563960352-25563960383,25563960416-25563960447,25563960448-25563960479,25563960480-25563960511,25563960512-25563960543,25563960544-25563960575,24845238272-24845254655,24845241280-24845241311,24845241088-24845241119,24845241120-24845241151,24845241152-24845241183,24845241184-24845241215,24845241216-24845241247,24845241248-24845241279,24845241312-24845241343,24428789760-24428806143,24428798048-24428798079,24428797952-24428797983,24428797984-24428798015,24428798016-24428798047,24428798080-24428798111,24428798112-24428798143,24428798144-24428798175,24428798176-24428798207,30060560384-30060576767,30060564864-30060564895,30060564736-30060564767,30060564768-30060564799,30060564800-30060564831,30060564832-30060564863,30060564896-30060564927,30060564928-30060564959,30060564960-30060564991,29459251200-29459267583,29459253824-29459253855,29459253760-29459253791,29459253792-29459253823,29459253856-29459253887,29459253888-29459253919,29459253920-29459253951,29459253952-29459253983,29459253984-29459254015,26775191552-26775207935,26775194912-26775194943,26775194880-26775194911,26775194944-26775194975,26775194976-26775195007,26775195008-26775195039,26775195040-26775195071,26775195072-26775195103,26775195104-26775195135,31391449088-31391465471,31391464544-31391464575,31391464448-31391464479,31391464480-31391464511,31391464512-31391464543,31391464576-31391464607,31391464608-31391464639,31391464640-31391464671,31391464672-31391464703,11743182848-11743199231,11743196672-11743196703,11743196704-11743196735,11743196736-11743196767,11743196768-11743196799,11743196800-11743196831,11743196832-11743196863,11743196864-11743196895,11743196896-11743196927";
        let (l, range) = parse_range(x);
        let mut read_data = vec![0; l as usize];
        let mut pos:Vec<(u64, u64)> = Vec::with_capacity(range.len());
        let ret = reader.read_multi_range(&mut read_data, &range, &mut pos);
        println!("hash is {}", data_hash(&read_data));
        assert!(ret.is_ok());
    }
}
