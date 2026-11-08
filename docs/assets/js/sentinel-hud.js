/* ==========================================================================
   NDAP CLOUD / [⌘K] SOVEREIGN CYBER SENTINEL & TERMINAL HUD
   Interactive GCC Enterprise Threat Hunting, Compliance, and Telemetry Engine.
   Features:
     - Global Command Palette [⌘K] / [Ctrl+K]
     - Live Interactive Terminal CLI with Packet & IOC Dissection
     - Gulf Sovereign Cloud Compliance Auditing (NCA ECC, SAMA, DESC, NIA)
     - Industrial SCADA / OT Modbus & DNP3 Analysis
     - Context-Aware AI Security Assistant for GCC Infrastructure
   ========================================================================== */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.NdapSentinelHud = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const COMMAND_REGISTRY = {
    'help': {
      desc: 'Display available terminal commands & quick actions',
      exec: () => `
<div style="color:#38bdf8; font-weight:700; margin-bottom:6px;">AVAILABLE SENTINEL COMMANDS:</div>
  <span style="color:#f59e0b;">scan &lt;ip&gt;</span>           - Inspect IP for C2 beaconing, entropy & ThreatFox reputation
  <span style="color:#f59e0b;">gcc-compliance</span>      - Audit Saudi NCA ECC-1:2018, UAE DESC, SAMA & Q-CERT residency
  <span style="color:#f59e0b;">scada-check</span>         - Inspect industrial Modbus TCP & DNP3 packet streams
  <span style="color:#f59e0b;">sync-ioc</span>            - Fetch and sync remote ThreatFox indicators
  <span style="color:#f59e0b;">mitre &lt;technique&gt;</span>   - Query MITRE ATT&CK enterprise and ICS matrix
  <span style="color:#f59e0b;">status</span>              - Output in-country sovereign sensor telemetry & dropped packet rate
  <span style="color:#f59e0b;">clear</span>               - Clear terminal output
  <span style="color:#f59e0b;">pilot</span>               - Open ThatJoint pilot request dialog
`
    },

    'status': {
      desc: 'Output sensor health and zero-copy packet statistics',
      exec: () => `
<div style="border:1px solid #1f2a3e; padding:10px; background:#0b1019; border-radius:6px;">
  <div style="color:#34d399; font-weight:700;">🟢 SENSOR SYSTEM: SOVEREIGN OPERATIONAL</div>
  <div style="color:#94a3b8; font-size:12px; margin-top:4px;">
    • Architecture: Pure Memory-Safe Rust (zero C dependencies)<br>
    • Kernel Interface: Linux AF_PACKET Zero-Copy Ring (0.00% dropped pkts)<br>
    • Active GCC Nodes: Riyadh Core (24.71°N), Dubai PoP (25.20°N), Doha Hub (25.28°N)<br>
    • Current Packet Rate: 2,410,850 pkts/s across 18 monitored VPCs<br>
    • In-Country Data Residency: 100% Verified (0.00 bytes exported abroad)
  </div>
</div>
`
    },

    'gcc-compliance': {
      desc: 'Audit Saudi NCA, UAE DESC, SAMA, and Qatar NCSA compliance',
      exec: () => `
<div style="color:#38bdf8; font-weight:700; margin-bottom:6px;">🇸🇦 🇦🇪 🇶🇦 GCC SOVEREIGN COMPLIANCE AUDIT MATRIX:</div>
<table style="width:100%; border-collapse:collapse; font-size:11.5px; margin-top:4px;">
  <tr style="border-bottom:1px solid #1f2a3e; color:#64748b; text-align:left;">
    <th style="padding:4px 6px;">MANDATE / REGULATION</th>
    <th style="padding:4px 6px;">JURISDICTION</th>
    <th style="padding:4px 6px;">DATA RESIDENCY</th>
    <th style="padding:4px 6px;">STATUS</th>
  </tr>
  <tr style="border-bottom:1px solid rgba(31,42,62,0.6);">
    <td style="padding:4px 6px; color:#fff;">NCA ECC-1:2018 (Essential Cybersecurity Controls)</td>
    <td style="padding:4px 6px; color:#94a3b8;">Saudi Arabia (KSA)</td>
    <td style="padding:4px 6px; color:#38bdf8;">100% In-Kingdom</td>
    <td style="padding:4px 6px; color:#34d399; font-weight:700;">✓ CERTIFIED</td>
  </tr>
  <tr style="border-bottom:1px solid rgba(31,42,62,0.6);">
    <td style="padding:4px 6px; color:#fff;">SAMA Cyber Security Framework</td>
    <td style="padding:4px 6px; color:#94a3b8;">Saudi Central Bank</td>
    <td style="padding:4px 6px; color:#38bdf8;">Financial VPC Tier-A</td>
    <td style="padding:4px 6px; color:#34d399; font-weight:700;">✓ AUDITED</td>
  </tr>
  <tr style="border-bottom:1px solid rgba(31,42,62,0.6);">
    <td style="padding:4px 6px; color:#fff;">DESC Cloud Security Standard (ISR v2.0)</td>
    <td style="padding:4px 6px; color:#94a3b8;">Dubai, UAE</td>
    <td style="padding:4px 6px; color:#38bdf8;">UAE Sovereign Cloud</td>
    <td style="padding:4px 6px; color:#34d399; font-weight:700;">✓ APPROVED</td>
  </tr>
  <tr style="border-bottom:1px solid rgba(31,42,62,0.6);">
    <td style="padding:4px 6px; color:#fff;">NCSA National Info Assurance (NIA v2.0)</td>
    <td style="padding:4px 6px; color:#94a3b8;">State of Qatar</td>
    <td style="padding:4px 6px; color:#38bdf8;">Doha Sovereign Node</td>
    <td style="padding:4px 6px; color:#34d399; font-weight:700;">✓ COMPLIANT</td>
  </tr>
</table>
<div style="margin-top:8px; font-size:11px; color:#34d399;">
  ✔ Zero packet payloads or unredacted enterprise telemetry ever cross Gulf sovereign borders.
</div>
`
    },

    'scada-check': {
      desc: 'Deep packet inspection on Modbus TCP and DNP3 industrial OT',
      exec: () => `
<div style="color:#f59e0b; font-weight:700; margin-bottom:4px;">⚡ INDUSTRIAL OT & SCADA DISSECTION ENGINE:</div>
<div style="font-size:12px; color:#cbd5e1; line-height:1.6;">
  [SCADA-01] Protocol: <b>Modbus TCP (Port 502)</b> · Source: 192.168.44.12:49182 -> Target: PLC-04 (Eastern Province Grid)<br>
  • Unit Identifier: 0x01 | Function Code: 0x03 (Read Holding Registers)<br>
  • Register Range: 40001 - 40016 | Anomaly Score: 0.02 (Legitimate Telemetry Poll)<br>
  [SCADA-02] Protocol: <b>DNP3 / IEC-60870-5-104 (Port 20000)</b> · Substation Feeder 08<br>
  • Function: Direct Operate | Status: Verified Cryptographic Hash (HMAC-SHA256)<br>
  <span style="color:#34d399; font-weight:700;">✓ SCADA Sensor Integrity: 0 unauthorized function code injections detected.</span>
</div>
`
    },

    'sync-ioc': {
      desc: 'Fetch latest indicators from ThreatFox and sovereign feeds',
      exec: () => `
<div style="color:#38bdf8;">⏳ Synchronizing threat indicators via secure TLS feed...</div>
<div style="margin-top:6px; color:#cbd5e1;">
  • abuse.ch ThreatFox: +1,240 new indicators ingested (C2, Cobalt Strike, Lumma)<br>
  • GCC Regional CERT Feed: +84 targeted Middle East APT IP/Domain indicators<br>
  • Memory Bloom Filter updated: 24,190 active IOCs in-RAM lookup (&lt; 40ns per packet)
</div>
<div style="color:#34d399; font-weight:700; margin-top:4px;">✔ Threat Intelligence synchronized successfully!</div>
`
    }
  };

  class NdapSentinelHud {
    constructor(options = {}) {
      this.drawerId = options.drawerId || 'sentinelDrawerRoot';
      this.isOpen = false;
      this.history = [];
      this.historyIndex = -1;

      this.init();
    }

    init() {
      this.renderDrawer();
      this.bindEvents();
    }

    renderDrawer() {
      let root = document.getElementById(this.drawerId);
      if (!root) {
        root = document.createElement('div');
        root.id = this.drawerId;
        document.body.appendChild(root);
      }

      root.innerHTML = `
        <div class="sentinel-backdrop" id="sentinelBackdrop"></div>
        <aside class="sentinel-drawer" id="sentinelDrawer" role="dialog" aria-modal="true" aria-label="Sovereign Cyber Sentinel">
          <div class="sentinel-head">
            <div class="sentinel-brand">
              <span class="sentinel-badge-pulse"></span>
              <div>
                <strong>NDAP SOVEREIGN SENTINEL</strong>
                <small>GCC Sovereign Cloud · In-Country Defense HUD</small>
              </div>
            </div>
            <button class="sentinel-close" id="sentinelCloseBtn" aria-label="Close Terminal [Esc]">&times;</button>
          </div>

          <!-- Quick Action Chips -->
          <div class="sentinel-chips">
            <button type="button" class="chip-btn" data-cmd="gcc-compliance">🇸🇦 GCC Compliance</button>
            <button type="button" class="chip-btn" data-cmd="scan 10.0.9.44">🎯 Beacon Hunt</button>
            <button type="button" class="chip-btn" data-cmd="scada-check">⚡ SCADA / OT</button>
            <button type="button" class="chip-btn" data-cmd="sync-ioc">🔄 Sync ThreatFox</button>
            <button type="button" class="chip-btn" data-cmd="status">📊 Status</button>
          </div>

          <!-- Terminal Output Screen -->
          <div class="sentinel-terminal" id="sentinelTerminalBody">
            <div class="term-line term-banner">
              ═════════════════════════════════════════════════════════════════════════<br>
              &nbsp;&nbsp;NDAP CLOUD / SOVEREIGN CYBER SENTINEL ENGINE [v2.4.0-gcc]<br>
              &nbsp;&nbsp;Pure Rust Core · Zero-Copy Linux AF_PACKET · GCC In-Country Certified<br>
              ═════════════════════════════════════════════════════════════════════════<br>
              Type <b style="color:#f59e0b;">'help'</b> to view commands, or click the quick chips above.<br>
              Press <b style="color:#38bdf8;">[Esc]</b> or <b style="color:#38bdf8;">[⌘K]</b> to toggle terminal HUD.
            </div>
          </div>

          <!-- Input Command Prompt -->
          <form class="sentinel-form" id="sentinelForm" onsubmit="return false;">
            <span class="prompt-sym">gcc-soc@ndap:~$</span>
            <input type="text" class="sentinel-input" id="sentinelInput" placeholder="Enter command or ask security question (e.g. 'gcc-compliance', 'scada-check')..." autocomplete="off" spellcheck="false" />
            <button type="submit" class="sentinel-run-btn">Run ↵</button>
          </form>
        </aside>
      `;

      // Apply Inline Acrylic HUD Styles
      this.injectStyles();
    }

    injectStyles() {
      if (document.getElementById('sentinelHudStyles')) return;
      const style = document.createElement('style');
      style.id = 'sentinelHudStyles';
      style.textContent = `
        .sentinel-backdrop {
          position: fixed; inset: 0; background: rgba(3, 5, 8, 0.78);
          backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px);
          z-index: 2500; opacity: 0; pointer-events: none;
          transition: opacity 0.3s cubic-bezier(0.16, 1, 0.3, 1);
        }
        .sentinel-backdrop.active { opacity: 1; pointer-events: auto; }

        .sentinel-drawer {
          position: fixed; top: 0; right: 0; bottom: 0;
          width: min(680px, 94vw);
          background: #090e17;
          border-left: 1px solid #1f2a3e;
          box-shadow: -20px 0 60px rgba(0, 0, 0, 0.85);
          z-index: 2600;
          display: flex; flex-direction: column;
          transform: translateX(105%);
          transition: transform 0.38s cubic-bezier(0.22, 1, 0.36, 1);
          color: #f1f5f9;
          font-family: 'IBM Plex Mono', monospace;
        }
        .sentinel-drawer.open { transform: translateX(0); }

        .sentinel-head {
          display: flex; justify-content: space-between; align-items: center;
          padding: 16px 22px; border-bottom: 1px solid #1f2a3e;
          background: #0d1421;
        }
        .sentinel-brand { display: flex; align-items: center; gap: 12px; }
        .sentinel-brand strong {
          display: block; font-size: 13.5px; letter-spacing: 0.08em;
          color: #fff; font-family: 'Barlow Condensed', sans-serif; font-size: 18px;
        }
        .sentinel-brand small {
          display: block; font-size: 10px; color: #94a3b8; font-family: 'DM Sans', sans-serif;
        }
        .sentinel-badge-pulse {
          width: 10px; height: 10px; border-radius: 50%;
          background: #10b981; box-shadow: 0 0 0 4px rgba(16, 185, 129, 0.25);
          animation: sentinelPulse 2s infinite;
        }
        @keyframes sentinelPulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.6; transform: scale(1.2); }
        }

        .sentinel-close {
          width: 32px; height: 32px; border: 1px solid #1f2a3e;
          border-radius: 50%; background: transparent; color: #94a3b8;
          font-size: 18px; display: flex; align-items: center; justify-content: center;
          cursor: pointer; transition: all 0.2s;
        }
        .sentinel-close:hover { color: #fff; border-color: #38bdf8; background: rgba(56, 189, 248, 0.1); }

        .sentinel-chips {
          display: flex; gap: 8px; padding: 12px 20px;
          border-bottom: 1px solid #1f2a3e; background: #070b12;
          overflow-x: auto; white-space: nowrap; scrollbar-width: none;
        }
        .sentinel-chips::-webkit-scrollbar { display: none; }
        .chip-btn {
          background: #0e1624; border: 1px solid #1f2a3e; color: #cbd5e1;
          padding: 6px 12px; font-size: 11px; border-radius: 4px;
          cursor: pointer; font-family: 'DM Sans', sans-serif; font-weight: 500;
          transition: all 0.15s ease;
        }
        .chip-btn:hover {
          border-color: #38bdf8; color: #38bdf8; background: rgba(56, 189, 248, 0.1);
        }

        .sentinel-terminal {
          flex: 1; padding: 18px 20px; overflow-y: auto;
          background: #06090f; font-size: 12px; line-height: 1.6;
        }
        .term-line { margin-bottom: 14px; word-break: break-word; }
        .term-banner { color: #64748b; font-size: 11px; margin-bottom: 16px; }
        .term-cmd { color: #38bdf8; font-weight: 600; }

        .sentinel-form {
          display: flex; align-items: center; gap: 10px;
          padding: 14px 20px; border-top: 1px solid #1f2a3e;
          background: #0a0f19;
        }
        .prompt-sym { color: #10b981; font-weight: 700; font-size: 12px; white-space: nowrap; }
        .sentinel-input {
          flex: 1; background: transparent; border: none; outline: none;
          color: #fff; font-family: 'IBM Plex Mono', monospace; font-size: 12.5px;
        }
        .sentinel-run-btn {
          background: #0284c7; border: none; color: #fff;
          padding: 6px 14px; font-size: 11px; font-family: 'IBM Plex Mono', monospace;
          border-radius: 4px; cursor: pointer; transition: opacity 0.2s;
        }
        .sentinel-run-btn:hover { opacity: 0.9; }
      `;
      document.head.appendChild(style);
    }

    bindEvents() {
      const backdrop = document.getElementById('sentinelBackdrop');
      const closeBtn = document.getElementById('sentinelCloseBtn');
      const form = document.getElementById('sentinelForm');
      const input = document.getElementById('sentinelInput');

      if (backdrop) backdrop.addEventListener('click', () => this.close());
      if (closeBtn) closeBtn.addEventListener('click', () => this.close());

      // Global hotkey: Command+K or Ctrl+K
      document.addEventListener('keydown', (e) => {
        if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
          e.preventDefault();
          this.toggle();
        } else if (e.key === 'Escape' && this.isOpen) {
          this.close();
        }
      });

      // Quick chip clicks
      const chips = document.querySelectorAll('.chip-btn');
      chips.forEach((btn) => {
        btn.addEventListener('click', () => {
          const cmd = btn.getAttribute('data-cmd');
          this.executeCommand(cmd);
        });
      });

      // Submit form
      if (form && input) {
        form.addEventListener('submit', (e) => {
          e.preventDefault();
          const val = input.value.trim();
          if (val) {
            this.executeCommand(val);
            input.value = '';
          }
        });
      }
    }

    open() {
      this.isOpen = true;
      document.getElementById('sentinelBackdrop')?.classList.add('active');
      document.getElementById('sentinelDrawer')?.classList.add('open');
      document.body.classList.add('sentinel-open');
      setTimeout(() => document.getElementById('sentinelInput')?.focus(), 200);
    }

    close() {
      this.isOpen = false;
      document.getElementById('sentinelBackdrop')?.classList.remove('active');
      document.getElementById('sentinelDrawer')?.classList.remove('open');
      document.body.classList.remove('sentinel-open');
    }

    toggle() {
      if (this.isOpen) {
        this.close();
      } else {
        this.open();
      }
    }

    executeCommand(cmdText) {
      const terminal = document.getElementById('sentinelTerminalBody');
      if (!terminal) return;

      const trimmed = cmdText.trim();
      const parts = trimmed.split(/\s+/);
      const root = parts[0].toLowerCase();
      const arg = parts.slice(1).join(' ');

      // Add user command echo
      const echoDiv = document.createElement('div');
      echoDiv.className = 'term-line';
      echoDiv.innerHTML = `<span style="color:#10b981;">gcc-soc@ndap:~$</span> <span class="term-cmd">${trimmed}</span>`;
      terminal.appendChild(echoDiv);

      if (root === 'clear') {
        terminal.innerHTML = '';
        return;
      }

      if (root === 'pilot') {
        this.close();
        if (typeof window.openInquiryModal === 'function') {
          window.openInquiryModal('demo');
        }
        return;
      }

      const outDiv = document.createElement('div');
      outDiv.className = 'term-line';

      if (COMMAND_REGISTRY[root]) {
        outDiv.innerHTML = COMMAND_REGISTRY[root].exec(arg);
      } else if (root === 'scan') {
        outDiv.innerHTML = this.simulateScan(arg || '10.0.9.44');
      } else if (root === 'mitre') {
        outDiv.innerHTML = this.simulateMitre(arg || 'T1071');
      } else {
        // AI Security Assistant Fallback
        outDiv.innerHTML = this.generateAiResponse(trimmed);
      }

      terminal.appendChild(outDiv);
      terminal.scrollTop = terminal.scrollHeight;
    }

    simulateScan(ip) {
      return `
<div style="border:1px solid #1f2a3e; padding:10px; background:#0b1019; border-radius:6px;">
  <div style="color:#ef4444; font-weight:700;">⚠️ BEACONING CLUSTER DETECTED: ${ip}</div>
  <div style="font-size:12px; color:#cbd5e1; margin-top:6px; line-height:1.5;">
    • Target Destination: 198.51.100.44:8443 (External Port)<br>
    • Observed Interval Count: 42 connections over 168.0s<br>
    • Mean Inter-Arrival Time (Δt): <b>4.002 seconds</b><br>
    • Coefficient of Variation (CV): <b>0.078</b> (&lt; 0.20 threshold = High Confidence Periodic C2)<br>
    • MITRE Technique: <span style="color:#38bdf8;">T1071.001 (Web Protocols / C2 Channel)</span><br>
    • Action: Packet metadata retained in local Gulf VPC. Sensor isolation rule dispatched.
  </div>
</div>
`;
    }

    simulateMitre(tech) {
      return `
<div style="color:#38bdf8; font-weight:700;">MITRE ATT&CK KNOWLEDGE LOOKUP: ${tech.toUpperCase()}</div>
<div style="font-size:12px; color:#cbd5e1; margin-top:4px;">
  • Name: Application Layer Protocol (C2 Beaconing)<br>
  • Tactic: TA0011 (Command and Control)<br>
  • Detection Rule: ndap-detect/beaconing (Rust Periodicity Engine)<br>
  • Sensor Dissection: Wire-speed timestamping with zero kernel ring buffer drops.
</div>
`;
    }

    generateAiResponse(prompt) {
      const p = prompt.toLowerCase();
      if (p.includes('nca') || p.includes('saudi') || p.includes('residency') || p.includes('ecc')) {
        return `
<div style="color:#34d399; font-weight:600;">[NDAP AI SOVEREIGN ADVISOR]</div>
<div style="font-size:12px; color:#cbd5e1; margin-top:4px;">
  NDAP Cloud complies with <b>Saudi NCA ECC-1:2018</b> and the <b>Saudi Personal Data Protection Law (PDPL)</b>.
  Edge sensors operate inside your Saudi VPCs (e.g., Oracle Cloud Jeddah/Riyadh or Google Cloud Dammam).
  Packet payloads are dissected in-memory using pure memory-safe Rust and never leave the Kingdom.
</div>`;
      }

      if (p.includes('desc') || p.includes('dubai') || p.includes('uae')) {
        return `
<div style="color:#34d399; font-weight:600;">[NDAP AI SOVEREIGN ADVISOR]</div>
<div style="font-size:12px; color:#cbd5e1; margin-top:4px;">
  For UAE enterprises and government entities, NDAP adheres to the <b>Dubai Electronic Security Center (DESC) Cloud Security Standard (ISR v2.0)</b> and UAE Information Assurance (IA) regulations with localized UAE-North data centers.
</div>`;
      }

      if (p.includes('scada') || p.includes('modbus') || p.includes('oil') || p.includes('gas') || p.includes('ot')) {
        return `
<div style="color:#f59e0b; font-weight:600;">[NDAP AI SOVEREIGN ADVISOR]</div>
<div style="font-size:12px; color:#cbd5e1; margin-top:4px;">
  NDAP includes native protocol dissectors for <b>Modbus TCP (Port 502)</b>, <b>DNP3 (Port 20000)</b>, and <b>IEC-60870-5-104</b>. It detects unauthorized function codes, register tampering, and covert industrial tunneling across energy facilities and desalination plants.
</div>`;
      }

      return `
<div style="color:#94a3b8; font-size:12px;">
  Command not recognized. Type <b style="color:#f59e0b;">'help'</b> for available options or try <b style="color:#38bdf8;">'gcc-compliance'</b>, <b style="color:#38bdf8;">'scada-check'</b>, or <b style="color:#38bdf8;">'scan 10.0.9.44'</b>.
</div>`;
    }
  }

  return NdapSentinelHud;
}));
