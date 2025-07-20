import { networkInterfaces } from 'os';

export function getLocalIPv4(): string {
  const nets = networkInterfaces();
  for (const name of Object.keys(nets)) {
    const net = nets[name];
    if (!net) continue;
    for (const n of net) {
      if (n.family === 'IPv4' && !n.internal) return n.address;
    }
  }
  throw new Error('No external IPv4 address found.');
}
