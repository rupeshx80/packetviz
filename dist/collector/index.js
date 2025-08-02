"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.startCapture = startCapture;
exports.stopCapture = stopCapture;
const network_1 = require("../utils/network");
const os_1 = __importDefault(require("os"));
let pcap;
let pcapType = null;
try {
    pcap = require('pcap');
    pcapType = 'pcap';
    console.log('✅ Using pcap library');
}
catch {
    console.warn('pcap module not found, trying pcap2...');
    try {
        pcap = require('pcap2');
        pcapType = 'pcap2';
        console.log('✅ Using pcap2 library');
    }
    catch {
        console.warn('Neither pcap nor pcap2 found. Will try system-based approach.');
        pcapType = 'system';
    }
}
let pcapSession = null;
let systemProcess = null;
function startCapture(callback) {
    console.log('🔍 Starting packet capture initialization on Windows...');
    if (os_1.default.platform() !== 'win32') {
        console.warn('This configuration is optimized for Windows');
    }
    if (pcapType === 'system') {
        console.log('📡 Using system-based packet capture...');
        startSystemCapture(callback);
        return;
    }
    if (!pcap || !pcapType) {
        console.error('No packet capture library available');
        startSystemCapture(callback);
        return;
    }
    try {
        const localIP = (0, network_1.getLocalIPv4)();
        console.log(`Local IP: ${localIP}`);
        const interfaces = (0, network_1.getAllNetworkInterfaces)();
        console.log('Available network interfaces:');
        interfaces.forEach((iface, idx) => {
            console.log(`  ${idx}: ${iface.name} - ${iface.address}`);
        });
        let devices = pcap.findalldevs();
        console.log(`Found ${devices.length} network devices`);
        if (devices.length === 0) {
            throw new Error('No network devices found. Make sure WinPcap/Npcap is installed.');
        }
        devices.forEach((device, idx) => {
            console.log(`Device ${idx}: ${device.name || device.description} - ${device.description || 'No description'}`);
        });
        let device = devices.find(d => {
            const name = (d.name || '').toLowerCase();
            const desc = (d.description || '').toLowerCase();
            return !name.includes('loopback') &&
                !desc.includes('loopback') &&
                !desc.includes('vmware') &&
                !desc.includes('virtualbox') &&
                !desc.includes('hyper-v') &&
                !name.includes('npcap') &&
                (desc.includes('ethernet') || desc.includes('wireless') || desc.includes('wi-fi'));
        }) || devices[0];
        console.log(`Selected device: ${device.name || device.description}`);
        const filter = 'tcp and (not host 127.0.0.1)';
        console.log('Creating packet capture session...');
        pcapSession = pcapType === 'pcap2'
            ? pcap.createSession(device.name, {
                filter,
                buffer_size: 10 * 1024 * 1024,
                buffer_timeout: 10,
                monitor: false,
            })
            : pcap.createSession(device.name, filter);
        pcapSession.on('packet', (rawPacket) => {
            handlePacket(rawPacket, callback);
        });
        pcapSession.on('error', (error) => {
            console.error('Packet capture session error:', error);
            startSystemCapture(callback);
        });
        console.log('Packet capture session started ✅');
    }
    catch (error) {
        console.error('Failed to start packet capture:', error);
        startSystemCapture(callback);
    }
}
function handlePacket(rawPacket, callback) {
    try {
        const packet = pcap.decode.packet(rawPacket);
        if (!packet?.payload?.payload)
            return;
        let ipPacket, tcpPacket;
        if (pcapType === 'pcap2') {
            ipPacket = packet.payload.payload;
            tcpPacket = ipPacket.payload;
            if (!ipPacket.saddr?.addr || !ipPacket.daddr?.addr)
                return;
            const srcIP = ipPacket.saddr.addr.join('.');
            const destIP = ipPacket.daddr.addr.join('.');
            if (srcIP === '127.0.0.1' || destIP === '127.0.0.1')
                return;
            callback({
                srcIP,
                destIP,
                protocol: 'TCP',
                timestamp: new Date(),
                size: rawPacket.length,
                port: {
                    src: tcpPacket?.sport,
                    dest: tcpPacket?.dport,
                }
            });
        }
        else if (pcapType === 'pcap') {
            const ethernetPayload = packet.payload;
            if (ethernetPayload.ethertype !== 2048)
                return; // Not IPv4
            const ipPayload = ethernetPayload.payload;
            if (ipPayload.protocol !== 6)
                return; // Not TCP
            const tcpPayload = ipPayload.payload;
            const srcIP = ipPayload.saddr;
            const destIP = ipPayload.daddr;
            if (srcIP === '127.0.0.1' || destIP === '127.0.0.1')
                return;
            callback({
                srcIP,
                destIP,
                protocol: 'TCP',
                timestamp: new Date(),
                size: rawPacket.length,
                port: {
                    src: tcpPayload?.sport,
                    dest: tcpPayload?.dport,
                }
            });
        }
    }
    catch (packetError) {
        console.error('Error processing packet:', packetError);
        callback(null);
    }
}
function startSystemCapture(callback) {
    console.log('🖥️  Starting system-based packet capture...');
    tryNetstatCapture(callback);
}
function tryNetstatCapture(callback) {
    console.log('📊 Using netstat for network monitoring...');
    const interval = setInterval(() => {
        try {
            const { execSync } = require('child_process');
            const output = execSync('netstat -an', { encoding: 'utf8', timeout: 5000 });
            const lines = output.split('\n');
            const tcpLines = lines.filter((line) => line.includes('TCP') &&
                line.includes('ESTABLISHED') &&
                !line.includes('127.0.0.1') &&
                !line.includes('::1'));
            if (tcpLines.length > 0) {
                const randomLine = tcpLines[Math.floor(Math.random() * tcpLines.length)];
                const parts = randomLine.trim().split(/\s+/);
                if (parts.length >= 4) {
                    const [localIP, localPort] = parts[1].split(':');
                    const [remoteIP, remotePort] = parts[2].split(':');
                    if (localIP && remoteIP && localPort && remotePort) {
                        callback({
                            srcIP: localIP,
                            destIP: remoteIP,
                            protocol: 'TCP',
                            timestamp: new Date(),
                            size: Math.floor(Math.random() * 1500) + 64,
                            port: {
                                src: parseInt(localPort),
                                dest: parseInt(remotePort),
                            }
                        });
                    }
                }
            }
        }
        catch (error) {
            console.error('Error running netstat:', error);
            clearInterval(interval);
        }
    }, 2000);
    systemProcess = { kill: () => clearInterval(interval) };
}
function stopCapture() {
    console.log('🛑 Stopping packet capture...');
    if (pcapSession) {
        try {
            if (pcapSession.close)
                pcapSession.close();
            pcapSession = null;
            console.log('Packet capture session closed');
        }
        catch (error) {
            console.error('Error closing packet capture session:', error);
        }
    }
    if (systemProcess) {
        try {
            systemProcess.kill();
            systemProcess = null;
            console.log('System capture process stopped');
        }
        catch (error) {
            console.error('Error stopping system process:', error);
        }
    }
}
