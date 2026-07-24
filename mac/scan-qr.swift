// Collateral — macOS camera QR scanner. Opens the camera in a small preview window and uses
// AVFoundation's built-in QR detection; on the first QR seen it prints the decoded string to
// STDOUT and exits. Diagnostics go to STDERR. Cancel (Esc / close / 2-min timeout) exits 0 with
// no output. Run via `swift mac/scan-qr.swift` — no build step, no dependencies.
//
// Exit codes: 0 = got a QR (on stdout) OR cancelled (empty stdout); 2 = camera permission
// denied; 3 = no camera / capture setup failed.

import AVFoundation
import AppKit

let err = FileHandle.standardError
func die(_ tag: String, _ code: Int32) -> Never { err.write((tag + "\n").data(using: .utf8)!); exit(code) }

// 1. Camera authorization (prompts on first use; the prompt is attributed to the terminal app).
switch AVCaptureDevice.authorizationStatus(for: .video) {
case .authorized:
  break
case .notDetermined:
  let sem = DispatchSemaphore(value: 0)
  var granted = false
  AVCaptureDevice.requestAccess(for: .video) { granted = $0; sem.signal() }
  sem.wait()
  if !granted { die("CAMERA_DENIED", 2) }
default:
  die("CAMERA_DENIED", 2)
}

// 2. Capture session with a QR metadata output.
let session = AVCaptureSession()
guard let device = AVCaptureDevice.default(for: .video),
      let input = try? AVCaptureDeviceInput(device: device),
      session.canAddInput(input) else { die("NO_CAMERA", 3) }
session.addInput(input)

let output = AVCaptureMetadataOutput()
guard session.canAddOutput(output) else { die("NO_CAMERA", 3) }
session.addOutput(output)
output.metadataObjectTypes = [.qr]

// 3. App + preview window.
let app = NSApplication.shared
app.setActivationPolicy(.regular)

final class ScanDelegate: NSObject, AVCaptureMetadataOutputObjectsDelegate {
  var fired = false
  func metadataOutput(_ o: AVCaptureMetadataOutput, didOutput objs: [AVMetadataObject], from c: AVCaptureConnection) {
    guard !fired else { return }
    for obj in objs {
      if let mo = obj as? AVMetadataMachineReadableCodeObject, mo.type == .qr, let s = mo.stringValue {
        fired = true
        FileHandle.standardOutput.write((s + "\n").data(using: .utf8)!)
        session.stopRunning()
        DispatchQueue.main.async { NSApp.terminate(nil) }
        return
      }
    }
  }
}
let delegate = ScanDelegate()
output.setMetadataObjectsDelegate(delegate, queue: .main)

final class WinDelegate: NSObject, NSWindowDelegate {
  func windowWillClose(_ n: Notification) { NSApp.terminate(nil) } // close button = cancel
}
let winDelegate = WinDelegate()

let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 560, height: 440),
                      styleMask: [.titled, .closable], backing: .buffered, defer: false)
window.title = "Collateral — point at the other Mac's QR  ·  Esc to cancel"
window.isReleasedWhenClosed = false
window.delegate = winDelegate
window.center()
window.contentView?.wantsLayer = true

let preview = AVCaptureVideoPreviewLayer(session: session)
preview.videoGravity = .resizeAspectFill
preview.frame = window.contentView!.bounds
preview.autoresizingMask = [.layerWidthSizable, .layerHeightSizable]
window.contentView!.layer!.addSublayer(preview)

window.makeKeyAndOrderFront(nil)
app.activate(ignoringOtherApps: true)

// Esc cancels; a 2-minute timeout is a safety net so it never hangs forever.
NSEvent.addLocalMonitorForEvents(matching: .keyDown) { e in
  if e.keyCode == 53 { NSApp.terminate(nil) }
  return e
}
DispatchQueue.main.asyncAfter(deadline: .now() + 120) { NSApp.terminate(nil) }

DispatchQueue.global(qos: .userInitiated).async { session.startRunning() }
app.run()
