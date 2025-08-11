import { createRequire } from "module";
import { getLocalIPv4, getAllNetworkInterfaces } from "../utils/network";
import { spawn, ChildProcess, execSync } from "child_process";
import os from "os";

export interface PacketInfo {
  srcIP: string;
  destIP: string;
  protocol: string;
  timestamp: Date;
  size?: number;
  port?: {
    src?: number;
    dest?: number;
  };
}

// Use createRequire so we can load CommonJS modules in ESM/TS
const cjsRequire = createRequire(typeof __filename !== "undefined" ? __filename : "");

let pcap: any;
let pcapType: "pcap" | "pcap2" | "system" | null = null;

try {
  pcap = require("pcap");
  pcapType = "pcap";
  console.log("Using pcap library");
} catch (err) {
  console.error("Failed to load pcap:", err);
  console.warn("pcap module not found or failed, trying pcap2");
  try {
    pcap = require("pcap2");
    pcapType = "pcap2";
    console.log("Using pcap2 library");
  } catch (err2) {
    console.error("failed to load pcap2:", err2);
    console.warn("Neither pcap nor pcap2 found. Will try system-based approach.");
    pcapType = "system";
  }
}

let pcapSession: any = null;
let systemProcess: ChildProcess | null = null;

export function startCapture(callback: (packetInfo: PacketInfo | null) => void): void {
  console.log("Starting packet capture initialization on Windows");

  if (os.platform() !== "win32") {
    console.warn("This configuration is optimized for windows");
  }

  if (pcapType === "system") {
    console.log("Using system-based packet capture");
    startSystemCapture(callback);
    return;
  }

  if (!pcap || !pcapType) {
    console.error("No packet capture library available");
    startSystemCapture(callback);
    return;
  }

  try {
    const localIP = getLocalIPv4();
    console.log(`Local IP: ${localIP}`);

    const interfaces = getAllNetworkInterfaces();
    console.log("Available network interfaces:");
    interfaces.forEach((iface, idx) => {
      console.log(`  ${idx}: ${iface.name} - ${iface.address}`);
    });

    let devices: any[] = pcap.findalldevs();
    console.log(`Found ${devices.length} network devices`);

    if (devices.length === 0) {
      throw new Error("No network devices found. Make sure WinPcap/Npcap is installed.");
    }

    devices.forEach((device, idx) => {
      console.log(`Device ${idx}: ${device.name || device.description} - ${device.description || "No description"}`);
    });

    let device =
      devices.find((d) => {
        const name = (d.name || "").toLowerCase();
        const desc = (d.description || "").toLowerCase();
        return (
          !name.includes("loopback") &&
          !desc.includes("loopback") &&
          !desc.includes("vmware") &&
          !desc.includes("virtualbox") &&
          !desc.includes("hyper-v") &&
          !name.includes("npcap") &&
          (desc.includes("ethernet") || desc.includes("wireless") || desc.includes("wi-fi"))
        );
      }) || devices[0];

    console.log(`Selected device: ${device.name || device.description}`);

    const filter = "tcp and (not host 127.0.0.1)";
    console.log("Creating packet capture session...");

    pcapSession =
      pcapType === "pcap2"
        ? pcap.createSession(device.name, {
            filter,
            buffer_size: 10 * 1024 * 1024,
            buffer_timeout: 10,
            monitor: false,
          })
        : pcap.createSession(device.name, filter);

    pcapSession.on("packet", (rawPacket: Buffer) => {
      handlePacket(rawPacket, callback);
    });

    pcapSession.on("error", (error: Error) => {
      console.error("Packet capture session error:", error);
      startSystemCapture(callback);
    });

    console.log("Packet capture session started");
  } catch (error) {
    console.error("Failed to start packet capture:", error);
    startSystemCapture(callback);
  }
}

function handlePacket(rawPacket: Buffer, callback: (packetInfo: PacketInfo | null) => void) {
  try {
    const packet = pcap.decode.packet(rawPacket);
    if (!packet?.payload?.payload) return;

    let ipPacket, tcpPacket;

    if (pcapType === "pcap2") {
      ipPacket = packet.payload.payload;
      tcpPacket = ipPacket.payload;
      if (!ipPacket.saddr?.addr || !ipPacket.daddr?.addr) return;

      const srcIP = ipPacket.saddr.addr.join(".");
      const destIP = ipPacket.daddr.addr.join(".");
      if (srcIP === "127.0.0.1" || destIP === "127.0.0.1") return;

      callback({
        srcIP,
        destIP,
        protocol: "TCP",
        timestamp: new Date(),
        size: rawPacket.length,
        port: {
          src: tcpPacket?.sport,
          dest: tcpPacket?.dport,
        },
      });
    } else if (pcapType === "pcap") {
      const ethernetPayload = packet.payload;
      if (ethernetPayload.ethertype !== 2048) return;

      const ipPayload = ethernetPayload.payload;
      if (ipPayload.protocol !== 6) return;

      const tcpPayload = ipPayload.payload;

      const srcIP = ipPayload.saddr;
      const destIP = ipPayload.daddr;
      if (srcIP === "127.0.0.1" || destIP === "127.0.0.1") return;

      callback({
        srcIP,
        destIP,
        protocol: "TCP",
        timestamp: new Date(),
        size: rawPacket.length,
        port: {
          src: tcpPayload?.sport,
          dest: tcpPayload?.dport,
        },
      });
    }
  } catch (packetError) {
    console.error("Error processing packet:", packetError);
    callback(null);
  }
}

function startSystemCapture(callback: (packetInfo: PacketInfo | null) => void): void {
  console.log("Starting system-based packet capture");
  tryNetstatCapture(callback);
}

function tryNetstatCapture(callback: (packetInfo: PacketInfo | null) => void): void {
  console.log("Using netstat for network monitoring");

  const interval = setInterval(() => {
    try {
      const output = execSync("netstat -an", { encoding: "utf8", timeout: 5000 });
      const lines = output.split("\n");

      const tcpLines: string[] = lines.filter(
        (line: string) =>
          line.includes("TCP") &&
          line.includes("ESTABLISHED") &&
          !line.includes("127.0.0.1") &&
          !line.includes("::1")
      );

      if (tcpLines.length > 0) {
        const randomLine = tcpLines[Math.floor(Math.random() * tcpLines.length)];
        const parts = randomLine.trim().split(/\s+/);

        if (parts.length >= 4) {
          const [localIP, localPort] = parts[1].split(":");
          const [remoteIP, remotePort] = parts[2].split(":");

          if (localIP && remoteIP && localPort && remotePort) {
            callback({
              srcIP: localIP,
              destIP: remoteIP,
              protocol: "TCP",
              timestamp: new Date(),
              size: Math.floor(Math.random() * 1500) + 64,
              port: {
                src: parseInt(localPort),
                dest: parseInt(remotePort),
              },
            });
          }
        }
      }
    } catch (error) {
      console.error("Error running netstat:", error);
      clearInterval(interval);
    }
  }, 2000);

  systemProcess = { kill: () => clearInterval(interval) } as any;
}

export function stopCapture(): void {
  console.log("Stopping packet capture");

  if (pcapSession) {
    try {
      if (pcapSession.close) pcapSession.close();
      pcapSession = null;
      console.log("Packet capture session closed");
    } catch (error) {
      console.error("Error closing packet capture session:", error);
    }
  }

  if (systemProcess) {
    try {
      systemProcess.kill();
      systemProcess = null;
      console.log("System capture process stopped");
    } catch (error) {
      console.error("Error stopping system process:", error);
    }
  }
}
