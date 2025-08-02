import { networkInterfaces } from 'os';

export function getLocalIPv4(): string {
  const nets = networkInterfaces();
  
  for (const name of Object.keys(nets)) {
    const net = nets[name];
    if (!net) continue;
    
    for (const netInterface of net) {
      if (netInterface.family === 'IPv4' && 
          !netInterface.internal && 
          netInterface.address !== '127.0.0.1') {
        return netInterface.address;
      }
    }
  }
  
  throw new Error('No external IPv4 address found.');
}

export function getAllNetworkInterfaces(): Array<{name: string, address: string}> {
  const nets = networkInterfaces();
  const interfaces: Array<{name: string, address: string}> = [];
  
  for (const [name, net] of Object.entries(nets)) {
    if (!net) continue;
    
    for (const netInterface of net) {
      if (netInterface.family === 'IPv4' && !netInterface.internal) {
        interfaces.push({ name, address: netInterface.address });
      }
    }
  }
  
  return interfaces;
}
