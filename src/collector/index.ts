import { getLocalIPv4 } from "../utils/network";
import pcap from "pcap";

export interface PacketInfo {
  srcIP: string;
  destIP: string;
  protocol: string;
  timestamp: Date;
}

export function startCapture(callback: (packetInfo: PacketInfo) => void) {
  const localIP = getLocalIPv4();
  const devices = pcap.findalldevs();
  const device = devices.length > 0 ? devices[0].name : '';
  const filter = 'ip proto \\tcp';
  const pcapSession = pcap.createSession(device, {
    filter,
    buffer_size: 10 * 1024 * 1024,
  });

  pcapSession.on('packet', function (rawPacket) {
    const packet = pcap.decode.packet(rawPacket);
    const ipPacket = packet.payload.payload;

    if (!ipPacket) return;

    callback({
      srcIP: ipPacket.saddr?.addr?.join('.') ?? 'unknown',
      destIP: ipPacket.daddr?.addr?.join('.') ?? 'unknown',
      protocol: 'TCP',
      timestamp: new Date()
    });
  });
}
