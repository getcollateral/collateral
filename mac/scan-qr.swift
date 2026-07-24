// Collateral - macOS camera QR scanner. Opens the camera in a small preview window and runs
// the Vision framework on each frame to find a QR code (macOS's AVCaptureMetadataOutput does
// NOT support QR detection - that's iOS-only - so we use Vision). On the first QR it prints the
// decoded string to STDOUT and exits 0; cancel (Esc / close / 2-min timeout) exits 0 with no
// output. Diagnostics go to STDERR. Run via `swift mac/scan-qr.swift` - no build step, no deps.
//
// Exit codes: 0 = got a QR (stdout) or cancelled (empty stdout); 2 = camera permission denied;
// 3 = no camera / capture setup failed.

import AVFoundation
import Vision
import AppKit

let errOut = FileHandle.standardError
func die(_ tag: String, _ code: Int32) -> Never { errOut.write((tag + "\n").data(using: .utf8)!); exit(code) }

let app = NSApplication.shared
app.setActivationPolicy(.regular)

final class WinDelegate: NSObject, NSWindowDelegate {
  func windowWillClose(_ n: Notification) { NSApp.terminate(nil) } // close button = cancel
}
let winDelegate = WinDelegate()

final class Scanner: NSObject, AVCaptureVideoDataOutputSampleBufferDelegate {
  let session = AVCaptureSession()
  var fired = false
  var window: NSWindow?

  func start() {
    guard let device = AVCaptureDevice.default(for: .video),
          let input = try? AVCaptureDeviceInput(device: device),
          session.canAddInput(input) else { die("NO_CAMERA", 3) }
    session.addInput(input)

    let vout = AVCaptureVideoDataOutput()
    vout.alwaysDiscardsLateVideoFrames = true
    vout.setSampleBufferDelegate(self, queue: DispatchQueue(label: "collateral.frames"))
    guard session.canAddOutput(vout) else { die("NO_CAMERA", 3) }
    session.addOutput(vout)

    let preview = AVCaptureVideoPreviewLayer(session: session)
    preview.videoGravity = .resizeAspectFill
    let view = NSView(frame: NSRect(x: 0, y: 0, width: 560, height: 440))
    view.layer = preview            // layer-hosting view (set layer before wantsLayer)
    view.wantsLayer = true

    let w = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 560, height: 440),
                     styleMask: [.titled, .closable], backing: .buffered, defer: false)
    w.title = "Collateral - point at the other Mac's QR  ·  Esc to cancel"
    w.isReleasedWhenClosed = false
    w.delegate = winDelegate
    w.contentView = view
    w.center()
    w.makeKeyAndOrderFront(nil)
    window = w
    app.activate(ignoringOtherApps: true)

    DispatchQueue.global(qos: .userInitiated).async { self.session.startRunning() }
  }

  func captureOutput(_ o: AVCaptureOutput, didOutput sb: CMSampleBuffer, from c: AVCaptureConnection) {
    guard !fired, let pixelBuffer = CMSampleBufferGetImageBuffer(sb) else { return }
    let req = VNDetectBarcodesRequest()
    req.symbologies = [.qr]
    try? VNImageRequestHandler(cvPixelBuffer: pixelBuffer, options: [:]).perform([req])
    for r in (req.results ?? []) where r.symbology == .qr {
      if let payload = r.payloadStringValue, !fired {
        fired = true
        FileHandle.standardOutput.write((payload + "\n").data(using: .utf8)!)
        session.stopRunning()
        DispatchQueue.main.async { NSApp.terminate(nil) }
        return
      }
    }
  }
}
let scanner = Scanner()

// Camera authorization - async (no blocking semaphore), so the app run loop is free to show
// the window as soon as access is granted.
switch AVCaptureDevice.authorizationStatus(for: .video) {
case .authorized:
  DispatchQueue.main.async { scanner.start() }
case .notDetermined:
  AVCaptureDevice.requestAccess(for: .video) { granted in
    DispatchQueue.main.async { if granted { scanner.start() } else { die("CAMERA_DENIED", 2) } }
  }
default:
  die("CAMERA_DENIED", 2)
}

NSEvent.addLocalMonitorForEvents(matching: .keyDown) { e in
  if e.keyCode == 53 { NSApp.terminate(nil) } // Esc
  return e
}
DispatchQueue.main.asyncAfter(deadline: .now() + 120) { NSApp.terminate(nil) }
app.run()
