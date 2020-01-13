/*
 * Copyright 2020-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package winlab.nctu.flowrule;

import com.google.common.collect.ImmutableSet;
import org.onosproject.cfg.ComponentConfigService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.onosproject.core.CoreService;
import org.onosproject.core.ApplicationId;
import org.onosproject.net.flow.FlowRuleService;
import org.onosproject.net.flow.FlowRule;
import org.onosproject.net.flow.DefaultFlowRule;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onlab.packet.IpPrefix;
import org.onlab.packet.Ip4Address;
import org.onosproject.net.DeviceId;
import org.onlab.packet.Ethernet;
import org.onosproject.core.GroupId;
import org.onosproject.net.group.*;

import java.util.Dictionary;
import java.util.List;
import java.util.Properties;
import java.nio.ByteBuffer;

import static org.onlab.util.Tools.get;

/**
 * ONOS flow rule API demo application.
 */
@Component(immediate = true,
           service = {SomeInterface.class},
           property = {
               "someProperty=Some Default String Value",
           })
public class AppComponent implements SomeInterface {

    private final Logger log = LoggerFactory.getLogger(getClass());

    /** Some configurable property. */
    private String someProperty;

    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected GroupService groupService;
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected FlowRuleService flowRuleService;

    private ApplicationId appId;

    @Activate
    protected void activate() {
        appId = coreService.registerApplication("winlab.nctu.flowrule");
        cfgService.registerProperties(getClass());
        log.info("Flow-rule demo app Started");
        flowRuleDemo();
    }

    @Deactivate
    protected void deactivate() {
        flowRuleService.removeFlowRulesById(appId);
        removeInterfaceGroups();
        cfgService.unregisterProperties(getClass(), false);
        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
    }

    @Override
    public void flowRuleDemo() {
        installInterfaceGroup(1, "of:0000000000000002", 1);
        installInterfaceGroup(2, "of:0000000000000002", 2);

        installFlowRule(Ethernet.TYPE_ARP, "10.0.0.2", 2, "of:0000000000000001");
        installFlowRule(Ethernet.TYPE_ARP, "10.0.0.2", 1, "of:0000000000000002");
        installFlowRule(Ethernet.TYPE_ARP, "10.0.0.1", 2, "of:0000000000000002");
        installFlowRule(Ethernet.TYPE_ARP, "10.0.0.1", 1, "of:0000000000000001");

        installFlowRule(Ethernet.TYPE_IPV4, "10.0.0.2/32", 2, "of:0000000000000001");
        installFlowRule(Ethernet.TYPE_IPV4, "10.0.0.2/32", 1, "of:0000000000000002");
        installFlowRule(Ethernet.TYPE_IPV4, "10.0.0.1/32", 2, "of:0000000000000002");
        installFlowRule(Ethernet.TYPE_IPV4, "10.0.0.1/32", 1, "of:0000000000000001");
    }

    private void installInterfaceGroup(int outPort, String did, int gid) {
        TrafficTreatment tt = DefaultTrafficTreatment.builder()
                .setOutput(PortNumber.portNumber(outPort))
                .build();
        GroupBucket bucket = DefaultGroupBucket.createIndirectGroupBucket(tt);
        GroupBuckets buckets = new GroupBuckets(List.of(bucket));
        GroupKey key = new DefaultGroupKey(ByteBuffer.allocate(4).putInt(gid).array());
        GroupDescription groupDesc = new DefaultGroupDescription(DeviceId.deviceId(did), GroupDescription.Type.INDIRECT, buckets, key, gid, appId);
        groupService.addGroup(groupDesc);
    }

    private void removeInterfaceGroups() {
        DeviceId did = DeviceId.deviceId("of:0000000000000002");
        GroupKey key = new DefaultGroupKey(ByteBuffer.allocate(4).putInt(1).array());
        groupService.removeGroup(did, key, appId);
        key = new DefaultGroupKey(ByteBuffer.allocate(4).putInt(2).array());
        groupService.removeGroup(did, key, appId);
    }

    private void installFlowRule(short ethType, String dstIp, int outPort, String did) {
        TrafficSelector.Builder tsb = DefaultTrafficSelector.builder().matchEthType(ethType);
        if (ethType == Ethernet.TYPE_ARP) {
            tsb.matchArpTpa(Ip4Address.valueOf(dstIp));
        } else {
            tsb.matchIPDst(IpPrefix.valueOf(dstIp));
        }

        boolean isOfdpa = did.equals("of:0000000000000002");
        TrafficTreatment.Builder ttb = DefaultTrafficTreatment.builder();
        if (isOfdpa) {
            ttb.group(new GroupId(outPort));
        } else {
            ttb.setOutput(PortNumber.portNumber(outPort));
        }

        FlowRule flow = DefaultFlowRule.builder()
                .forDevice(DeviceId.deviceId(did))
                .makePermanent()
                .withPriority(40001)
                .forTable(isOfdpa ? 60 : 0)
                .withSelector(tsb.build())
                .withTreatment(ttb.build())
                .fromApp(appId)
                .build();
        flowRuleService.applyFlowRules(flow);
    }
}
