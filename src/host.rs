fn host_rx_loop(ring_num: usize, netmap: &mut NetmapDescriptor) {
        println!("HOST RX loop for ring {:?}", ring_num);
        println!("Rx rings: {:?}", netmap.get_rx_rings());

        scheduler::set_self_affinity(CpuSet::single(ring_num)).expect("setting affinity failed");
        scheduler::set_self_policy(Policy::Fifo, 20).expect("setting sched policy failed");

        loop {
            if let Some(_) = netmap.poll(netmap::Direction::Input) {
                for ring in netmap.rx_iter() {
                    for (slot, _) in ring.iter() {
                        //println!("HOST RX pkt");
                        //packet::dump_input(&buf);
                        slot.set_flags(netmap::NS_FORWARD as u16);
                    }
                    ring.set_flags(netmap::NR_FORWARD as u32);
                }
            }
        }
}
