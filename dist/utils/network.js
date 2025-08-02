"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getLocalIPv4 = getLocalIPv4;
exports.getAllNetworkInterfaces = getAllNetworkInterfaces;
const os_1 = require("os");
function getLocalIPv4() {
    const nets = (0, os_1.networkInterfaces)();
    for (const name of Object.keys(nets)) {
        const net = nets[name];
        if (!net)
            continue;
        for (const netInterface of net) {
            // Check for IPv4, not internal, and not loopback
            if (netInterface.family === 'IPv4' &&
                !netInterface.internal &&
                netInterface.address !== '127.0.0.1') {
                return netInterface.address;
            }
        }
    }
    throw new Error('No external IPv4 address found.');
}
function getAllNetworkInterfaces() {
    const nets = (0, os_1.networkInterfaces)();
    const interfaces = [];
    for (const [name, net] of Object.entries(nets)) {
        if (!net)
            continue;
        for (const netInterface of net) {
            if (netInterface.family === 'IPv4' && !netInterface.internal) {
                interfaces.push({ name, address: netInterface.address });
            }
        }
    }
    return interfaces;
}
