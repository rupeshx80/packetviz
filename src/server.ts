import express from "express";
import { Server } from "socket.io";
import dotenv from "dotenv";
import { startCapture } from "./collector";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

const server = app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});

const io = new Server(server, {
  cors: {
    origin: "*", 
  },
});

app.get("/", (_req, res) => {
  res.send("PacketViz backend running, lets go");
});

startCapture(packet => {
  console.log(`[${packet.protocol}] ${packet.srcIP} → ${packet.destIP}`);
});

io.on("connection", (socket) => {
  console.log("Client connected:", socket.id);
  socket.on("disconnect", () => {
    console.log("Client disconnected:", socket.id);
  });
});

