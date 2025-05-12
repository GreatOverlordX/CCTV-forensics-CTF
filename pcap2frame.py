# tite chose for simplicity since it converted the pcap into frames 
# (for video reconstruction then converted into .mp4 format as seen in the code below).

import os
import re
import subprocess
from scapy.all import rdpcap, TCP, IP, Ether

def extract_frames_from_buffer(buffer, boundary):
    frame_count = 0
    offset = 0
    boundary_bytes = boundary.encode()

    while (offset := buffer.find(boundary_bytes, offset)) != -1:
        next_boundary = buffer.find(boundary_bytes, offset + len(boundary_bytes))
        if next_boundary == -1:
            break

        part = buffer[offset:next_boundary]
        try:
            content_length_match = re.search(r'Content-Length:\s*(\d+)', part.decode('utf-8', errors='ignore'))
        except UnicodeDecodeError:
            content_length_match = re.search(r'Content-Length:\s*(\d+)', part.decode('latin1', errors='ignore'))

        if not content_length_match:
            offset = next_boundary
            continue

        content_length = int(content_length_match.group(1))
        header_end = part.find(b'\r\n\r\n')
        if header_end == -1:
            offset = next_boundary
            continue

        jpeg_start = offset + header_end + 4
        jpeg_end = jpeg_start + content_length
        jpeg_data = buffer[jpeg_start:jpeg_end]

        filename = f'frame_{frame_count:04d}.jpg'
        with open(filename, 'wb') as f:
            f.write(jpeg_data)
        print(f'Saved frame {frame_count}')
        frame_count += 1

        offset = next_boundary

    print(f'Extraction complete: {frame_count} frames saved.')
    create_video_from_frames(frame_count)

def create_video_from_frames(frame_count):
    fps = 10  # Change FPS to match your stream's real rate
    output_file = 'output_video.mp4'

    cmd = [
        'ffmpeg', '-y', '-framerate', str(fps), '-i', 'frame_%04d.jpg',
        '-c:v', 'libx264', '-pix_fmt', 'yuv420p', output_file
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f'❌ FFmpeg error: {result.stderr}')
        return
    print(f'🎞️ Video created successfully! ==> {output_file}')

def process_pcap(file_path):
    packets = rdpcap(file_path)
    tcp_data = b''

    for packet in packets:
        if packet.haslayer(TCP):
            payload = bytes(packet[TCP].payload)
            if payload:
                tcp_data += payload

    print("Finished reading PCAP. Processing MJPEG stream...")
    extract_frames_from_buffer(tcp_data, "--BoundaryString")

if __name__ == "__main__":
    pcap_file = input("Input location of pcap file ---> ")
    process_pcap(pcap_file)
