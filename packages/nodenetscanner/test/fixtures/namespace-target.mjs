import dgram from "node:dgram";
import net from "node:net";

const tcpPort = Number(process.env.NODENETSCANNER_TCP_PORT ?? "18080");
const udp4Port = Number(process.env.NODENETSCANNER_UDP4_PORT ?? "18082");
const udp6Port = Number(process.env.NODENETSCANNER_UDP6_PORT ?? "18084");

const servers = [];

for (const options of [
  { host: "0.0.0.0", ipv6Only: false },
  { host: "::", ipv6Only: true },
]) {
  const server = net.createServer((socket) => socket.end());
  servers.push(server);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen({ port: tcpPort, ...options }, resolve);
  });
}

for (const { type, port } of [
  { type: "udp4", port: udp4Port },
  { type: "udp6", port: udp6Port },
]) {
  const socket = dgram.createSocket({
    type,
    ipv6Only: type === "udp6",
  });
  socket.on("message", (message, remote) => {
    socket.send(message, remote.port, remote.address);
  });
  servers.push(socket);
  await new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(
      {
        port,
        address: type === "udp4" ? "0.0.0.0" : "::",
      },
      resolve,
    );
  });
}

console.log("READY");

const close = () => {
  for (const server of servers) server.close();
};
process.once("SIGTERM", close);
process.once("SIGINT", close);
