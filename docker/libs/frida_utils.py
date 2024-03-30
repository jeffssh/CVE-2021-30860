import frida, sys, time, hexdump
from threading import Lock
stdout_mutex = Lock()

def load_trace_file(id):
	#script_file = f"./frida/scripts/shared-trace.js"
	script_file = f"./frida/scripts/{id}-trace.js"
	#script_file = f"./frida/scripts/exception-test.js"
	with open(script_file, 'r') as f: return f.read()


def on_message(pname, pid, message, data, script):
    if message["type"] == 'send':
        p = message["payload"]
        # used by flushSend in JS to ensure all messages are printed in a blocking fashion.
        # frida will wait for an ACK message before resuming
        if p == "[!!BUFFER!!]":
            script.post({'type': 'input', 'payload': "go"})
        elif  p == "[frida!!PAUSE!!]":
            stdout_mutex.acquire()
            print(f"[{pname}:{pid}] Script paused execution, resuming in 3 seconds")
            stdout_mutex.release()
            time.sleep(3)
            stdout_mutex.acquire()
            print(f"[{pname}:{pid}] resuming execution")
            stdout_mutex.release()
            script.post({'type': 'input', 'payload': "go"})
        else:
            # is there an attached buffer?
            if data:
                stdout_mutex.acquire()
                print(f"[{pname}:{pid}]", p)
                stdout_mutex.release()
                hexdump.hexdump(data)
            else:
                stdout_mutex.acquire()
                print(f"[{pname}:{pid}]", p)
                stdout_mutex.release()
    else:
        stdout_mutex.acquire()
        print(message)
        stdout_mutex.release()
    sys.stdout.flush()


# refactor TODO: validate this works
def trace(host):
    dev = frida.get_device_manager().add_remote_device(host)
    print(f"[+] Got dev handle:", dev)
    # format is (attach, wait)
    # why do these names differ? Just to be difficult (not really)
    target_processes = [
        # uncomment as needed
        #("UserNotificationsUIThumbnailProvider", "com.apple.UserNotificationsUIKit.ThumbnailProvider"),
        #("com.apple.quicklook.ThumbnailsAgent","com.apple.quicklook.ThumbnailsAgent"),
        ("IMTranscoderAgent","com.apple.imtranscoding.IMTranscoderAgent"),
    ]
    # attach has friendly names, wait has different names
    spawn_process_targets = []
    running_processes = dev.enumerate_processes()
    for attach_process_id, wait_process_id in target_processes:
        attached = False
        for rp in running_processes:
            if attach_process_id == rp.name:
                print(f"[+] Found {attach_process_id} as pid: ", rp.pid)
                active_session = dev.attach(rp.pid)
                script = active_session.create_script(load_trace_file(wait_process_id))
                script.on('message', lambda message, data, pname=wait_process_id, pid=rp.pid, script=script: on_message(pname, pid, message, data, script))
                script.load()
                print(f"[+] resuming target process {attach_process_id}")
                active_session.resume()
                attached = True
        if not attached:
            print(f"[+] Couldn't find {attach_process_id}, waiting for {wait_process_id} instead")
            spawn_process_targets.append(wait_process_id)
    
    # tried to attach to all processes
    # now must wait for the missing processes to spawn
    def on_spawned(spawn):
        if spawn.identifier in spawn_process_targets:
            print(f"[!] Target process {spawn.identifier} spawned, attaching")
            active_session = dev.attach(spawn.pid)
            print("[+] active frida session!, creating script")
            script = active_session.create_script(load_trace_file(spawn.identifier))
            script.on('message', lambda message, data, pname=spawn.identifier, pid=spawn.pid, script=script: on_message(spawn.identifier, spawn.pid, message, data, script))
            script.load()
            print(f"[+] resuming target process {spawn.identifier}")
            active_session.resume()
        dev.resume(spawn.pid)


    dev.on('spawn-added', on_spawned)
    dev.enable_spawn_gating()
    # block
    print("[+] blocking main thread, waiting for:", spawn_process_targets)
    sys.stdin.read()


# specific hooking of IMTransocderAgent
def imt(host):
    script_file = "./frida/scripts/ios-14.4-arm64-imt.js"
    target_process = "com.apple.imtranscoding.IMTranscoderAgent"
    print(f"[+] Running {script_file} on {host}")
    print(f"[+] Waiting for {target_process} to spawn")
    dev = frida.get_device_manager().add_remote_device(host)
    print(f"[+] Got dev handle:", dev)    
    dev.on('spawn-added', lambda spawn : imt_on_spawned(spawn, dev, target_process, script_file))
    dev.enable_spawn_gating()
    print("[+] blocking main thread, waiting for:", target_process)
    sys.stdin.read()


def imt_on_spawned(spawn, dev, target_process, script_file):
	if spawn.identifier == target_process:
		print(f"[!] Target process {target_process} spawned, attaching")
		active_session = dev.attach(spawn.pid)
		#print("[+] active frida session!, creating script")
		with open(script_file, 'r') as file:
			script_text = file.read()
		script = active_session.create_script(script_text)
		def on_message(spawn, message, data):
			#print('on_message:', spawn, message, data)
			if message["type"] == 'send':
				p = message["payload"]
				if p == "[!!BUFFER!!]":
					#print("[FRIDA] flushing buffer")
					script.post({'type': 'input', 'payload': "go"})
				elif p == "[!!BUG VALID HEAP!!]":
					# triggering bug
					print("=========================")
					print("🐛 magic is in the air 🐛")
					print("=========================")
					#for i in range(3, -1, -1):
					# TODO revert after finding dealloc gadget
					for i in range(-1, -1, -1):
						end = ""
						if i == 0:
							end = "\n"
						print(f"\r[+] Triggering bug in {i}...", end=end)
						time.sleep(1)
					script.post({'type': 'input', 'payload': "go"})
				elif p == "[!!BUG INVALID HEAP!!]":
					print(f"\r[-] Triggering bug but expected to fail...")
					script.post({'type': 'input', 'payload': "go"})
				elif  p == "[!!PAUSE!!]":
					#input("[*] Script paused execution, hit enter to continue...")
					print("[+] pausing execution for 10 seconds")
					time.sleep(10)
					print("[+] resuming execution")
					script.post({'type': 'input', 'payload': "go"})

				else:
					# is there an attached buffer?
					if data:
						print("[FRIDA]", p)
						hexdump.hexdump(data)
					else:
						print("[FRIDA]", p)
					
			else:
				print(message)
			sys.stdout.flush()

		
		script.on('message', lambda message, data: on_message(spawn, message, data))
		script.load()
		
		#script.exports.init()
		#print("[+] resuming target process")
		
		active_session.resume()
		# need this for some reason when testing with settings
		# thought active_session.resume would suffice?
		dev.resume(spawn.pid)
		#print("[?] waiting for stdin...")
		#sys.stdin.read()



	else: 
		dev.resume(spawn.pid)
		print('[+] Resuming', spawn)