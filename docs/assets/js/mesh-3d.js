/* ==========================================================================
   NDAP CLOUD / 3D SOVEREIGN CYBER MESH & THREAT RADAR
   Vanilla Three.js Interactive GCC Sovereign Cyber Topology.
   Features:
     - 3D Wireframe Cyber Globe & Topology Grid
     - Gulf Sovereign Hubs: Riyadh (KSA), Dubai (UAE), Abu Dhabi, Doha (Qatar),
       Manama (Bahrain), Kuwait City, Muscat (Oman), plus Global Gateways
     - Real-Time Laser Telemetry Arcs with Animated Packet Streams
     - OrbitControls with Smooth Camera Easing & Zone Transitions
     - 3D World Hotspot Anchors with Live In-Country Throughput Metrics
   ========================================================================== */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.NdapCyberMesh = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  // Gulf Capital & Sovereign Hub World Positions (Spherical Radius ~ 10)
  const SOVEREIGN_HUBS = [
    {
      id: 'riyadh',
      name: 'Riyadh Sovereign Core (الرياض)',
      country: 'Kingdom of Saudi Arabia',
      zone: 'riyadh',
      lat: 24.7136, lon: 46.6753,
      compliance: 'NCA ECC-1:2018 · SAMA CSF',
      throughput: '1.42 M pkts/s',
      status: 'In-Country Data Residency Certified',
      color: 0x38bdf8,
      isCore: true
    },
    {
      id: 'dubai',
      name: 'Dubai Edge Sensor Cluster (دبي)',
      country: 'United Arab Emirates',
      zone: 'dubai',
      lat: 25.2048, lon: 55.2708,
      compliance: 'DESC Cloud Security Tier-3',
      throughput: '890 K pkts/s',
      status: 'Wire-Speed Sensor Online',
      color: 0x10b981
    },
    {
      id: 'abudhabi',
      name: 'Abu Dhabi Defense Node (أبوظبي)',
      country: 'United Arab Emirates',
      zone: 'dubai',
      lat: 24.4539, lon: 54.3773,
      compliance: 'UAE IA Regulation Compliant',
      throughput: '620 K pkts/s',
      status: 'Zero Telemetry Egress',
      color: 0x10b981
    },
    {
      id: 'doha',
      name: 'Doha Sovereign Hub (الدوحة)',
      country: 'State of Qatar',
      zone: 'doha',
      lat: 25.2854, lon: 51.5310,
      compliance: 'NCSA NIA Policy v2.0',
      throughput: '510 K pkts/s',
      status: 'Q-CERT Integrated',
      color: 0xa855f7
    },
    {
      id: 'manama',
      name: 'Manama Financial Gateway (المنامة)',
      country: 'Kingdom of Bahrain',
      zone: 'sama',
      lat: 26.2285, lon: 50.5860,
      compliance: 'AWS Bahrain Sovereign Banking',
      throughput: '410 K pkts/s',
      status: 'Banking Mesh Active',
      color: 0xf59e0b
    },
    {
      id: 'kuwait',
      name: 'Kuwait City Energy Mesh (الكويت)',
      country: 'State of Kuwait',
      zone: 'scada',
      lat: 29.3759, lon: 47.9774,
      compliance: 'CBK Cybersecurity Framework',
      throughput: '480 K pkts/s',
      status: 'Industrial OT Active',
      color: 0x38bdf8
    },
    {
      id: 'rastanura',
      name: 'Ras Tanura Industrial OT (رأس تنورة)',
      country: 'Eastern Province, KSA',
      zone: 'scada',
      lat: 26.6749, lon: 50.1583,
      compliance: 'Aramco CCC · Modbus/DNP3',
      throughput: '340 K pkts/s',
      status: 'SCADA Anomaly Detection Active',
      color: 0xf59e0b,
      isOT: true
    }
  ];

  // International Telemetry Gateways
  const GLOBAL_GATEWAYS = [
    { id: 'frankfurt', name: 'Frankfurt Threat Gateway', lat: 50.1109, lon: 8.6821, color: 0x64748b },
    { id: 'london', name: 'London Financial Link', lat: 51.5074, lon: -0.1278, color: 0x64748b },
    { id: 'singapore', name: 'Singapore APAC Feed', lat: 1.3521, lon: 103.8198, color: 0x64748b }
  ];

  // Camera presets for zone transitions
  const ZONES = {
    'all': {
      id: 'all',
      camPos: { x: 12, y: 16, z: 22 },
      target: { x: 0, y: 0, z: 0 },
      title: 'Full GCC Sovereign Mesh',
      desc: 'Real-time telemetry exchange across GCC sovereign data centers and edge sensors.'
    },
    'riyadh': {
      id: 'riyadh',
      camPos: { x: 3, y: 11, z: 12 },
      target: { x: 2.2, y: 3.8, z: 6.8 },
      title: 'Riyadh NCA Sovereign Hub',
      desc: 'National Cybersecurity Authority (NCA ECC) in-country sovereign core and SAMA finance mesh.'
    },
    'dubai': {
      id: 'dubai',
      camPos: { x: 8, y: 10, z: 10 },
      target: { x: 4.6, y: 4.1, z: 5.6 },
      title: 'Dubai DESC Edge Sensor Cluster',
      desc: 'Dubai Electronic Security Center (DESC) certified wire-speed sensors with local retention.'
    },
    'scada': {
      id: 'scada',
      camPos: { x: 6, y: 13, z: 9 },
      target: { x: 3.2, y: 4.4, z: 6.0 },
      title: 'Oil & Gas / SCADA Industrial OT',
      desc: 'Deep packet inspection for Modbus TCP, DNP3, and IEC-60870-5-104 energy facilities.'
    },
    'sama': {
      id: 'sama',
      camPos: { x: 5, y: 11, z: 11 },
      target: { x: 3.8, y: 4.2, z: 5.9 },
      title: 'SAMA Financial & Banking Mesh',
      desc: 'Zero-trust network detection for interbank payments, SWIFT, and sovereign banking clouds.'
    }
  };

  function latLonToVector3(lat, lon, radius) {
    const phi = (90 - lat) * (Math.PI / 180);
    const theta = (lon + 180) * (Math.PI / 180);
    const x = -(radius * Math.sin(phi) * Math.cos(theta));
    const z = radius * Math.sin(phi) * Math.sin(theta);
    const y = radius * Math.cos(phi);
    return new THREE.Vector3(x, y, z);
  }

  class NdapCyberMesh {
    constructor(options = {}) {
      this.container = typeof options.container === 'string'
        ? document.getElementById(options.container)
        : options.container;

      this.currentZone = 'all';
      this.activeHub = null;
      this.hubMeshes = [];
      this.arcParticles = [];
      this.isTransitioning = false;
      this.transitionProgress = 1;
      this.camStartPos = new THREE.Vector3();
      this.camTargetPos = new THREE.Vector3();
      this.lookStart = new THREE.Vector3();
      this.lookTarget = new THREE.Vector3();

      if (this.container) {
        this.init();
      }
    }

    init() {
      if (typeof THREE === 'undefined') {
        console.warn('Three.js not loaded. Skipping 3D mesh initialization.');
        return;
      }

      const width = this.container.clientWidth || 800;
      const height = this.container.clientHeight || 520;

      // 1. Scene, Camera, Renderer
      this.scene = new THREE.Scene();
      this.scene.fog = new THREE.FogExp2(0x080b11, 0.025);

      this.camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
      const initialZone = ZONES['all'];
      this.camera.position.set(initialZone.camPos.x, initialZone.camPos.y, initialZone.camPos.z);
      this.camera.lookAt(initialZone.target.x, initialZone.target.y, initialZone.target.z);

      this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
      this.renderer.setSize(width, height);
      this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
      this.renderer.setClearColor(0x000000, 0);
      this.container.appendChild(this.renderer.domElement);

      // 2. OrbitControls
      if (typeof THREE.OrbitControls !== 'undefined') {
        this.controls = new THREE.OrbitControls(this.camera, this.renderer.domElement);
        this.controls.enableDamping = true;
        this.controls.dampingFactor = 0.05;
        this.controls.enableZoom = true;
        this.controls.minDistance = 8;
        this.controls.maxDistance = 45;
        this.controls.autoRotate = true;
        this.controls.autoRotateSpeed = 0.6;
        this.controls.maxPolarAngle = Math.PI * 0.85;
      }

      // 3. Build Sovereign Cyber Globe
      this.buildGlobe();

      // 4. Build Hub Nodes & Laser Arcs
      this.buildHubs();
      this.buildTelemetryArcs();

      // 5. Lighting
      const ambientLight = new THREE.AmbientLight(0xffffff, 0.7);
      this.scene.add(ambientLight);

      const dirLight = new THREE.DirectionalLight(0x38bdf8, 1.2);
      dirLight.position.set(20, 30, 20);
      this.scene.add(dirLight);

      const bluePoint = new THREE.PointLight(0x0284c7, 2, 50);
      bluePoint.position.set(0, 0, 0);
      this.scene.add(bluePoint);

      // 6. Resize Observer
      window.addEventListener('resize', () => this.onResize());
      if (window.ResizeObserver) {
        new ResizeObserver(() => this.onResize()).observe(this.container);
      }

      // 7. Raycaster for clicking Hub Nodes
      this.raycaster = new THREE.Raycaster();
      this.mouse = new THREE.Vector2();
      this.renderer.domElement.addEventListener('click', (e) => this.onPointerClick(e));

      // 8. Start Loop
      this.animate = this.animate.bind(this);
      requestAnimationFrame(this.animate);

      // Initial active zone details update
      this.updateDetails(initialZone.title, initialZone.desc);
    }

    buildGlobe() {
      const radius = 10;
      this.globeRadius = radius;

      // Outer Wireframe Sphere
      const globeGeo = new THREE.SphereGeometry(radius, 36, 36);
      const globeMat = new THREE.MeshBasicMaterial({
        color: 0x1e293b,
        wireframe: true,
        transparent: true,
        opacity: 0.22
      });
      this.globe = new THREE.Mesh(globeGeo, globeMat);
      this.scene.add(this.globe);

      // Inner Core Glow
      const coreGeo = new THREE.SphereGeometry(radius * 0.98, 32, 32);
      const coreMat = new THREE.MeshBasicMaterial({
        color: 0x070c14,
        transparent: true,
        opacity: 0.85
      });
      const core = new THREE.Mesh(coreGeo, coreMat);
      this.scene.add(core);

      // Equator & Gulf Meridian Rings
      const ringGeo = new THREE.RingGeometry(radius * 1.05, radius * 1.06, 64);
      const ringMat = new THREE.MeshBasicMaterial({
        color: 0x0284c7,
        side: THREE.DoubleSide,
        transparent: true,
        opacity: 0.35
      });
      const equator = new THREE.Mesh(ringGeo, ringMat);
      equator.rotation.x = Math.PI / 2;
      this.scene.add(equator);

      // Floating Particle Halo
      const particlesCount = 280;
      const partGeo = new THREE.BufferGeometry();
      const partPos = new Float32Array(particlesCount * 3);
      for (let i = 0; i < particlesCount * 3; i += 3) {
        const u = Math.random();
        const v = Math.random();
        const theta = u * 2.0 * Math.PI;
        const phi = Math.acos(2.0 * v - 1.0);
        const r = radius * (1.05 + Math.random() * 0.25);
        partPos[i] = r * Math.sin(phi) * Math.cos(theta);
        partPos[i + 1] = r * Math.sin(phi) * Math.sin(theta);
        partPos[i + 2] = r * Math.cos(phi);
      }
      partGeo.setAttribute('position', new THREE.BufferAttribute(partPos, 3));
      const partMat = new THREE.PointsMaterial({
        color: 0x38bdf8,
        size: 0.14,
        transparent: true,
        opacity: 0.6
      });
      this.halo = new THREE.Points(partGeo, partMat);
      this.scene.add(this.halo);
    }

    buildHubs() {
      const radius = this.globeRadius;

      SOVEREIGN_HUBS.forEach((hub) => {
        const pos = latLonToVector3(hub.lat, hub.lon, radius);

        // Core Beacon Dot
        const dotGeo = new THREE.SphereGeometry(hub.isCore ? 0.32 : 0.22, 16, 16);
        const dotMat = new THREE.MeshBasicMaterial({ color: hub.color });
        const dotMesh = new THREE.Mesh(dotGeo, dotMat);
        dotMesh.position.copy(pos);
        dotMesh.userData = hub;
        this.scene.add(dotMesh);
        this.hubMeshes.push(dotMesh);

        // Pulsing Ring Beacon
        const beaconGeo = new THREE.RingGeometry(0.3, 0.45, 24);
        const beaconMat = new THREE.MeshBasicMaterial({
          color: hub.color,
          side: THREE.DoubleSide,
          transparent: true,
          opacity: 0.75
        });
        const beacon = new THREE.Mesh(beaconGeo, beaconMat);
        beacon.position.copy(pos.clone().multiplyScalar(1.02));
        beacon.lookAt(pos.clone().multiplyScalar(2));
        this.scene.add(beacon);

        // Vertical Telemetry Pillar
        const pillarHeight = hub.isCore ? 1.6 : 0.9;
        const pillarGeo = new THREE.CylinderGeometry(0.04, 0.04, pillarHeight, 8);
        const pillarMat = new THREE.MeshBasicMaterial({
          color: hub.color,
          transparent: true,
          opacity: 0.65
        });
        const pillar = new THREE.Mesh(pillarGeo, pillarMat);
        const normal = pos.clone().normalize();
        pillar.position.copy(pos.clone().add(normal.clone().multiplyScalar(pillarHeight / 2)));
        pillar.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), normal);
        this.scene.add(pillar);
      });

      // Global Gateways
      GLOBAL_GATEWAYS.forEach((gw) => {
        const pos = latLonToVector3(gw.lat, gw.lon, radius);
        const gwGeo = new THREE.BoxGeometry(0.18, 0.18, 0.18);
        const gwMat = new THREE.MeshBasicMaterial({ color: gw.color, wireframe: true });
        const gwMesh = new THREE.Mesh(gwGeo, gwMat);
        gwMesh.position.copy(pos);
        this.scene.add(gwMesh);
      });
    }

    buildTelemetryArcs() {
      const radius = this.globeRadius;
      const riyadh = SOVEREIGN_HUBS.find(h => h.id === 'riyadh');
      const riyadhPos = latLonToVector3(riyadh.lat, riyadh.lon, radius);

      // Connect all other hubs to Riyadh Sovereign Core
      SOVEREIGN_HUBS.filter(h => h.id !== 'riyadh').forEach((hub) => {
        const hubPos = latLonToVector3(hub.lat, hub.lon, radius);
        this.createArc(hubPos, riyadhPos, hub.color);
      });

      // Connect Riyadh to Frankfurt and London Gateways
      GLOBAL_GATEWAYS.forEach((gw) => {
        const gwPos = latLonToVector3(gw.lat, gw.lon, radius);
        this.createArc(riyadhPos, gwPos, 0x475569);
      });
    }

    createArc(p1, p2, color) {
      const dist = p1.distanceTo(p2);
      const mid = p1.clone().add(p2).multiplyScalar(0.5);
      // Elevate midpoint above globe
      const altitude = this.globeRadius + dist * 0.28;
      mid.normalize().multiplyScalar(altitude);

      const curve = new THREE.QuadraticBezierCurve3(p1, mid, p2);
      const points = curve.getPoints(36);
      const geometry = new THREE.BufferGeometry().setFromPoints(points);

      const material = new THREE.LineBasicMaterial({
        color: color,
        transparent: true,
        opacity: 0.4
      });
      const line = new THREE.Line(geometry, material);
      this.scene.add(line);

      // Animated Laser Packet Particle on Arc
      const particleGeo = new THREE.SphereGeometry(0.12, 8, 8);
      const particleMat = new THREE.MeshBasicMaterial({ color: 0x38bdf8 });
      const particle = new THREE.Mesh(particleGeo, particleMat);
      this.scene.add(particle);

      this.arcParticles.push({
        mesh: particle,
        curve: curve,
        speed: 0.006 + Math.random() * 0.006,
        progress: Math.random()
      });
    }

    switchZone(zoneKey) {
      const zone = ZONES[zoneKey] || ZONES['all'];
      this.currentZone = zoneKey;

      if (this.controls) {
        this.controls.autoRotate = (zoneKey === 'all');
      }

      // Smooth camera transition
      this.camStartPos.copy(this.camera.position);
      this.camTargetPos.set(zone.camPos.x, zone.camPos.y, zone.camPos.z);
      this.lookStart.copy(this.controls ? this.controls.target : new THREE.Vector3());
      this.lookTarget.set(zone.target.x, zone.target.y, zone.target.z);

      this.isTransitioning = true;
      this.transitionProgress = 0;

      this.updateDetails(zone.title, zone.desc);
    }

    updateDetails(title, desc) {
      const titleEl = document.getElementById('meshZoneTitle');
      const descEl = document.getElementById('meshZoneDesc');
      if (titleEl) titleEl.innerText = title;
      if (descEl) descEl.innerText = desc;
    }

    onPointerClick(event) {
      const rect = this.renderer.domElement.getBoundingClientRect();
      this.mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
      this.mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;

      this.raycaster.setFromCamera(this.mouse, this.camera);
      const intersects = this.raycaster.intersectObjects(this.hubMeshes);

      if (intersects.length > 0) {
        const hub = intersects[0].object.userData;
        this.displayHubTelemetry(hub);
      }
    }

    displayHubTelemetry(hub) {
      const card = document.getElementById('meshHubTelemetry');
      if (!card) return;

      card.innerHTML = `
        <div style="font-family:'Barlow Condensed', sans-serif; font-size:22px; font-weight:600; text-transform:uppercase; color:#fff; display:flex; justify-content:space-between; align-items:center;">
          <span>${hub.name}</span>
          <span style="color:${hub.isCore ? '#38bdf8' : '#10b981'}; font-size:14px; font-family:'IBM Plex Mono', monospace;">● ONLINE</span>
        </div>
        <div style="font-size:12px; color:#94a3b8; margin:4px 0 10px;">${hub.country}</div>
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; font-size:11.5px; border-top:1px solid #1f2a3e; padding-top:10px;">
          <div>
            <span style="color:#64748b; text-transform:uppercase; font-size:10px;">Compliance</span><br>
            <b style="color:#34d399;">${hub.compliance}</b>
          </div>
          <div>
            <span style="color:#64748b; text-transform:uppercase; font-size:10px;">Throughput</span><br>
            <b style="color:#38bdf8;">${hub.throughput}</b>
          </div>
        </div>
        <div style="margin-top:10px; font-size:11px; color:#cbd5e1; background:rgba(56,189,248,0.08); padding:6px 10px; border-radius:4px; border-left:2px solid #38bdf8;">
          ${hub.status}
        </div>
      `;
      card.style.display = 'block';
    }

    onResize() {
      if (!this.container || !this.renderer || !this.camera) return;
      const width = this.container.clientWidth;
      const height = this.container.clientHeight || 520;
      this.camera.aspect = width / height;
      this.camera.updateProjectionMatrix();
      this.renderer.setSize(width, height);
    }

    animate() {
      requestAnimationFrame(this.animate);

      // Rotate Halo
      if (this.halo) {
        this.halo.rotation.y += 0.001;
      }

      // Smooth Camera Transition Easing
      if (this.isTransitioning) {
        this.transitionProgress += 0.025;
        const t = Math.min(this.transitionProgress, 1);
        const ease = t * (2 - t); // Quad ease-out

        this.camera.position.lerpVectors(this.camStartPos, this.camTargetPos, ease);
        if (this.controls) {
          this.controls.target.lerpVectors(this.lookStart, this.lookTarget, ease);
        }

        if (t >= 1) {
          this.isTransitioning = false;
        }
      }

      if (this.controls) {
        this.controls.update();
      }

      // Animate Laser Packet Particles on Arcs
      this.arcParticles.forEach((p) => {
        p.progress += p.speed;
        if (p.progress > 1) p.progress = 0;
        const pos = p.curve.getPoint(p.progress);
        p.mesh.position.copy(pos);
      });

      this.renderer.render(this.scene, this.camera);
    }
  }

  return NdapCyberMesh;
}));
