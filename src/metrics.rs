use ::influent;
use std::ops::Deref;
use influent::client::udp::UdpClient;
use influent::measurement::{Value,Measurement};

pub struct Client<'a> {
    inner: UdpClient<'a>,
}

impl<'a> Deref for Client<'a> {
    type Target = UdpClient<'a>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a> Client<'a> {
    pub fn new(metrics_server: &'a str) -> Client<'a> {
        Client { inner: influent::create_udp_client(vec![metrics_server]) }
    }

    pub fn send(&self, metrics: &[Metric]) {
        use influent::client::Client;
        use std::mem;
        let _ = self.inner.write_many(unsafe { mem::transmute(metrics) }, None);
    }
}

pub struct Metric<'a> {
    inner: Measurement<'a>,
}

impl<'a> Metric<'a> {
    pub fn new_with_tags(name: &'a str, tags: &'a [(&'a str, &'a str)]) -> Metric<'a> {
        let mut m = Measurement::new(name);

        for &(ref key, ref val) in tags {
            m.add_tag(key, val);
        }
        Metric { inner: m }
    }

    pub fn set_value(&mut self, val: i64) {
        self.inner.add_field("value", Value::Integer(val));
    }
}
