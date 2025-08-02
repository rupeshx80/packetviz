import express from "express";
import { Server } from "socket.io";
import dotenv from "dotenv";
import { startCapture, stopCapture } from "./collector/index";

dotenv.config();

try {
  const app = express();
  const PORT = process.env.PORT || 5000;

  //error handling for uncaught exceptions
  process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    process.exit(1);
  });

  process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
  });

  const server = app.listen(PORT, () => {
    console.log(`Server listening on port ${PORT}`);
  });

  const io = new Server(server, {
    cors: {
      origin: "*",
    },
  });

  //Track active connections
  let activeConnections = 0;

  startCapture((packet) => {
    if (!packet) return;

    const protocol = packet.protocol || 'Unknown';
    const srcIP = packet.srcIP || 'Unknown';
    const destIP = packet.destIP || 'Unknown';

    console.log(`[${protocol}] ${srcIP} → ${destIP}`);

    if (activeConnections > 0) {
      io.emit('packet', packet);
    }
  });

  app.get("/", (_req, res) => {
    res.send("PacketViz backend running, lets go");
  });

  // io.on("connection", (socket) => {
  //   activeConnections++;
  //   console.log(`Client connected: ${socket.id} (${activeConnections} active)`);

  //   socket.on("disconnect", () => {
  //     activeConnections--;
  //     console.log(`Client disconnected: ${socket.id} (${activeConnections} active)`);
  //   });

  //   socket.on("error", (error) => {
  //     console.error("Socket error:", error);
  //   });
  // });

  const gracefulShutdown = () => {
    console.log('Shutting down gracefully...');
    stopCapture();
    server.close(() => {
      console.log('HTTP server closed');
      process.exit(0);
    });
    setTimeout(() => {
      console.error('Forced shutdown');
      process.exit(1);
    }, 10000);
  };

  process.on('SIGTERM', gracefulShutdown);
  process.on('SIGINT', gracefulShutdown);

} catch (err) {
  console.error('Fatal error during boot:', err);
}
