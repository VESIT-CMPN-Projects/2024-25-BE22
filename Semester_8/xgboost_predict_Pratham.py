from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub

import simple_switch
from datetime import datetime
import pandas as pd
import joblib
import xgboost as xgb

class SimpleMonitor13(simple_switch.SimpleSwitch13):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
       
        # Blacklist to store attackers' IP addresses
        self.blacklist = set()
       
        # Load the pre-trained model
        try:
            self.flow_model = joblib.load('ddos_xgboost_model.joblib')
            self.logger.info("Model loaded successfully")
        except Exception as e:
            self.logger.error(f"Error loading model: {e}")
            raise

        # Start monitoring thread
        self.monitor_thread = hub.spawn(self._monitor)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

            self.flow_predict()

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        timestamp = datetime.now()
        timestamp = timestamp.timestamp()

        file0 = open("PredictFlowStatsfile.csv","w")
        file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond,label\n')
        body = ev.msg.body
        icmp_code = -1
        icmp_type = -1
        tp_src = 0
        tp_dst = 0
       
        flow_count = 0
       
        for stat in sorted([flow for flow in body if (flow.priority == 1) ], key=lambda flow:
            (flow.match['eth_type'],flow.match['ipv4_src'],flow.match['ipv4_dst'],flow.match['ip_proto'])):
           
            flow_count += 1
            ip_src = stat.match['ipv4_src']
            ip_dst = stat.match['ipv4_dst']
            ip_proto = stat.match['ip_proto']
           
            if stat.match['ip_proto'] == 1:
                icmp_code = stat.match['icmpv4_code']
                icmp_type = stat.match['icmpv4_type']
               
            elif stat.match['ip_proto'] == 6:
                tp_src = stat.match['tcp_src']
                tp_dst = stat.match['tcp_dst']

            elif stat.match['ip_proto'] == 17:
                tp_src = stat.match['udp_src']
                tp_dst = stat.match['udp_dst']

            flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)
         
            try:
                packet_count_per_second = stat.packet_count/stat.duration_sec
                packet_count_per_nsecond = stat.packet_count/stat.duration_nsec
            except:
                packet_count_per_second = 0
                packet_count_per_nsecond = 0
               
            try:
                byte_count_per_second = stat.byte_count/stat.duration_sec
                byte_count_per_nsecond = stat.byte_count/stat.duration_nsec
            except:
                byte_count_per_second = 0
                byte_count_per_nsecond = 0
               
            file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src,ip_dst, tp_dst,
                        stat.match['ip_proto'],icmp_code,icmp_type,
                        stat.duration_sec, stat.duration_nsec,
                        stat.idle_timeout, stat.hard_timeout,
                        stat.flags, stat.packet_count,stat.byte_count,
                        packet_count_per_second,packet_count_per_nsecond,
                        byte_count_per_second,byte_count_per_nsecond, 0))
       
        self.logger.info(f"Collected {flow_count} flows from switch {ev.msg.datapath.id}")
        file0.close()

    def flow_predict(self):
        try:
            predict_flow_dataset = pd.read_csv('PredictFlowStatsfile.csv')

            # Ensure we only predict if there are rows in the dataset
            if predict_flow_dataset.empty:
                self.logger.info("No flows to predict.")
                return

            # Store original IP addresses before processing
            attacker_ips = {}
            victim_ips = {}

            # Process the dataset similarly to the working example
            predict_flow_dataset.iloc[:, 2] = predict_flow_dataset.iloc[:, 2].str.replace('.', '')
           
            # Store original IP addresses and their no-dots versions
            for i in range(len(predict_flow_dataset)):
                if 'ip_src' in predict_flow_dataset.columns:
                    orig_ip = predict_flow_dataset.iloc[i, 3]
                    # Store original IPs before replacing dots
                    attacker_ips[orig_ip.replace('.', '')] = orig_ip
                   
                if 'ip_dst' in predict_flow_dataset.columns:
                    orig_ip = predict_flow_dataset.iloc[i, 5]
                    # Store original IPs before replacing dots
                    victim_ips[orig_ip.replace('.', '')] = orig_ip
           
            predict_flow_dataset.iloc[:, 3] = predict_flow_dataset.iloc[:, 3].str.replace('.', '')
            predict_flow_dataset.iloc[:, 5] = predict_flow_dataset.iloc[:, 5].str.replace('.', '')

            X_predict_flow = predict_flow_dataset.iloc[:, :-1].values
            X_predict_flow = X_predict_flow.astype('float64')
           
            # Convert to DMatrix for XGBoost prediction
            dpredict = xgb.DMatrix(X_predict_flow)
           
            # Predict probabilities and convert to binary
            y_flow_pred_prob = self.flow_model.predict(dpredict)
            y_flow_pred = [1 if pred > 0.5 else 0 for pred in y_flow_pred_prob]

            legitimate_traffic = 0
            ddos_traffic = 0
           
            # Track all possible attackers
            identified_attackers = []
            main_victim = None
            victim_count = 0
           
            for i in range(len(y_flow_pred)):
                if y_flow_pred[i] == 0:
                    legitimate_traffic = legitimate_traffic + 1
                else:
                    ddos_traffic = ddos_traffic + 1
                    victim_numeric = str(int(predict_flow_dataset.iloc[i, 5]))
                    attacker_numeric = str(int(predict_flow_dataset.iloc[i, 3]))
                   
                    # Try to find the original IP from the numeric version
                    if victim_numeric in victim_ips:
                        main_victim = victim_ips[victim_numeric]
                        victim_count += 1
                   
                    # Store the attacker IP if we can find it
                    if attacker_numeric in attacker_ips:
                        identified_attackers.append(attacker_ips[attacker_numeric])

            self.logger.info("------------------------------------------------------------------------------")
            total_traffic = legitimate_traffic + ddos_traffic
           
            if total_traffic == 0:
                self.logger.info("No traffic detected.")
            elif (legitimate_traffic/total_traffic*100) > 80:
                self.logger.info("Legitimate traffic detected...")
            else:
                self.logger.info("DDoS attack detected!")
               
                # Calculate the victim host number based on the IP
                if main_victim:
                    try:
                        victim_host = int(main_victim.split('.')[-1])
                        self.logger.info(f"Victim is host: h{victim_host} (IP: {main_victim})")
                    except:
                        self.logger.info(f"Victim IP: {main_victim}")
               
                # Apply mitigation if we have identified attackers
                if identified_attackers and main_victim:
                    self.logger.info(f"Identified {len(identified_attackers)} attacking IPs")
                    self.mitigate_ddos(identified_attackers, main_victim)

            self.logger.info("------------------------------------------------------------------------------")
           
            # Clear the file after processing
            file0 = open("PredictFlowStatsfile.csv","w")
            file0.write('timestamp,datapath_id,flow_id,ip_src,tp_src,ip_dst,tp_dst,ip_proto,icmp_code,icmp_type,flow_duration_sec,flow_duration_nsec,idle_timeout,hard_timeout,flags,packet_count,byte_count,packet_count_per_second,packet_count_per_nsecond,byte_count_per_second,byte_count_per_nsecond,label\n')
            file0.close()

        except Exception as e:
            self.logger.error(f"Prediction error: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
   
    def mitigate_ddos(self, attackers, victim_ip):
        """
        Install flow rules to completely block traffic from attacking hosts
        """
        # Filter unique attackers
        unique_attackers = list(set(attackers))
        
        # Only block attackers that are not already blocked
        new_attackers = [ip for ip in unique_attackers if ip not in self.blacklist]
        
        # Update blacklist
        self.blacklist.update(new_attackers)
        
        if not new_attackers:
            self.logger.info("No new attackers to block")
            return
        
        self.logger.info(f"Completely blocking {len(new_attackers)} attacking hosts for 5 minutes...")
        
        # Install blocking rules for each attacker in every datapath
        for dp in self.datapaths.values():
            self._block_hosts(dp, new_attackers)

    def _block_hosts(self, datapath, attacker_ips):
        """
        Install flow rules to completely block all traffic from attacker_ips
        regardless of destination
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Block each attacker completely
        for attacker_ip in attacker_ips:
            self.logger.info(f"Completely blocking all traffic from host {attacker_ip}")
            
            # Match: any traffic from the attacker (regardless of destination)
            match = parser.OFPMatch(
                eth_type=0x0800, # IPv4
                ipv4_src=attacker_ip
            )
            
            # Action: drop by setting empty action list
            actions = []
            
            # Install with high priority (higher than normal flows)
            self._add_flow(datapath, 3, match, actions, idle_timeout=300) # 5 minute timeout

    def _add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        """
        Install a flow entry to the datapath
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
       
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
       
        datapath.send_msg(mod)