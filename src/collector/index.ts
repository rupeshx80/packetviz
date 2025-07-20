import { getLocalIPv4 } from "../utils/network";
import { Cap, decoders } from "cap";

export interface PacketInfo {
  srcIP: string;
  destIP: string;
  protocol: string;
  timestamp: Date;
}

export function startCapture(callback: (packetInfo: PacketInfo) => void) {
  const c = new Cap();
  const device = Cap.findDevice(getLocalIPv4());
  const filter = 'ip and tcp';
  const bufSize = 10 * 1024 * 1024;
  const buffer = Buffer.alloc(65535);

  const linkType = c.open(device!, filter, bufSize, buffer);
  c.setMinBytes && c.setMinBytes(0);

  c.on('packet', (nbytes: number, trunc: boolean) => {
    if (linkType === 'ETHERNET') {
      const ret = decoders.Ethernet(buffer);

      if (ret.info.type === decoders.PROTOCOL.ETHERNET.IPV4) {
        const ip = decoders.IPV4(buffer, ret.offset);

        callback({
          srcIP: ip.info.srcaddr,
          destIP: ip.info.dstaddr,
          protocol: 'TCP',
          timestamp: new Date()
        });
      }
    }
  });
}
