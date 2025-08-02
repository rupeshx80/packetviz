declare module 'pcap2' {
  export interface Device {
    name: string;
    description?: string;
    addresses?: Array<{
      addr: string;
      netmask: string;
      broadaddr?: string;
      dstaddr?: string;
    }>;
  }

  export interface SessionOptions {
    filter?: string;
    buffer_size?: number;
    buffer_timeout?: number;
    monitor?: boolean;
  }

  export interface TCPPacket {
    sport?: number;
    dport?: number;
    flags?: number;
    payload?: any;
  }

  export interface IPPacket {
    saddr?: {
      addr: number[];
    };
    daddr?: {
      addr: number[];
    };
    protocol?: number;
    payload?: TCPPacket;
  }

  export interface EthernetPacket {
    payload?: IPPacket;
  }

  export interface DecodedPacket {
    payload?: EthernetPacket;
  }

  export interface PcapSession {
    on(event: 'packet', callback: (rawPacket: Buffer) => void): void;
    on(event: 'error', callback: (error: Error) => void): void;
    close(): void;
  }

  export function findalldevs(): Device[];
  
  export function createSession(device?: string, options?: SessionOptions): PcapSession;
  
  export namespace decode {
    function packet(rawPacket: Buffer): DecodedPacket;
  }
}