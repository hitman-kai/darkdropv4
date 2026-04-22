'use client';
import React, { useRef, useMemo, useState, useEffect } from 'react';
import { Canvas, useFrame, extend, ThreeElement } from '@react-three/fiber';
import { OrbitControls, Effects } from '@react-three/drei';
import { UnrealBloomPass } from 'three-stdlib';
import * as THREE from 'three';

extend({ UnrealBloomPass });

declare module '@react-three/fiber' {
    interface ThreeElements {
        unrealBloomPass: ThreeElement<typeof UnrealBloomPass>
    }
}

const ParticleSwarm = () => {
    const meshRef = useRef<THREE.InstancedMesh>(null!);
    const count = 20000;
    const dummy = useMemo(() => new THREE.Object3D(), []);
    const target = useMemo(() => new THREE.Vector3(), []);
    const pColor = useMemo(() => new THREE.Color(), []);

    // Pre-calculate everything that doesn't change per frame for CPU performance
    const particlesData = useMemo(() => {
        const data = [];
        for (let i = 0; i < count; i++) {
            const n = i / count;
            data.push({
                n,
                zRaw: (n - 0.5) * 2.0,
                profile: Math.pow(Math.sin(n * Math.PI), 0.8),
                edgeFade: Math.pow(Math.sin(n * Math.PI), 1.5),
                baseHue: 0.38 + (1.0 - n) * 0.08,
                rx: (Math.random() - 0.5) * 2,
                ry: (Math.random() - 0.5) * 2,
                rz: (Math.random() - 0.5) * 2,
                pos: new THREE.Vector3(0, 0, 0)
            });
        }
        return data;
    }, [count]);

    const material = useMemo(() => new THREE.MeshBasicMaterial({ color: 0xffffff }), []);

    const geometry = useMemo(() => new THREE.SphereGeometry(0.12, 8, 8), []);

    useFrame((state) => {
        if (!meshRef.current) return;
        const time = state.clock.getElapsedTime() * 1.6;

        meshRef.current.rotation.y = Math.sin(time * 0.15) * 0.1;
        meshRef.current.rotation.z = Math.cos(time * 0.1) * 0.05;
        meshRef.current.rotation.x = Math.sin(time * 0.12) * 0.05;

        for (let i = 0; i < count; i++) {
            const p = particlesData[i];

            // LIQUID CYLINDER
            const r = 55 * p.profile + Math.sin(p.n * Math.PI * 6 - time * 3) * 25 * p.profile;

            const theta = i * 2.4 + time * 3.0 + (p.zRaw * 5.0);
            const tubeX = Math.cos(theta) * r;
            const tubeY = Math.sin(theta) * r;

            const waveX = Math.sin(p.zRaw * 2.0 - time * 1.5) * 120 + Math.cos(p.zRaw * 1.2 + time * 1.2) * 60;
            const waveY = Math.cos(p.zRaw * 1.8 + time * 1.4) * 90 + Math.sin(p.zRaw * 1.0 - time * 1.0) * 40;

            const turbulence = 6 + Math.sin(p.n * 40 - time * 6) * 6;

            const x = waveX + tubeX + (Math.sin(time * 4 + p.rx * 20) * turbulence);
            const y = waveY + tubeY + (Math.cos(time * 4 + p.ry * 20) * turbulence);
            const z = p.zRaw * 350 + (Math.sin(time * 4 + p.rz * 20) * turbulence);

            target.set(x, y, z);
            p.pos.lerp(target, 0.08);

            // Fast matrix translation
            dummy.matrix.makeTranslation(p.pos.x, p.pos.y, p.pos.z);
            meshRef.current.setMatrixAt(i, dummy.matrix);

            // COLOR & GLOW
            const baseLight = 0.25;
            const energyPulse = Math.pow(Math.max(0, Math.sin(p.n * 12 - time * 5)), 6) * 0.9;
            const finalLightness = (baseLight + energyPulse) * p.edgeFade;

            pColor.setHSL(p.baseHue, 0.95, finalLightness);
            meshRef.current.setColorAt(i, pColor);
        }
        meshRef.current.instanceMatrix.needsUpdate = true;
        if (meshRef.current.instanceColor) meshRef.current.instanceColor.needsUpdate = true;
    });

    return <instancedMesh ref={meshRef} args={[geometry, material, count]} />;
};

export default function SnakeBackground() {
    const [active, setActive] = useState(false);

    useEffect(() => {
        const handleProcessEvent = (e: any) => setActive(e.detail.active);
        window.addEventListener('darkdrop-processing-create', handleProcessEvent);
        return () => window.removeEventListener('darkdrop-processing-create', handleProcessEvent);
    }, []);

    return (
        <div className={`fixed inset-0 z-0 pointer-events-none transition-opacity duration-1000 ${active ? 'opacity-90' : 'opacity-0'}`}>
            <Canvas camera={{ position: [0, 0, 480], fov: 50 }}>
                <fog attach="fog" args={['#000000', 250, 600]} />
                <ParticleSwarm />
                <OrbitControls enableZoom={false} enablePan={false} autoRotate={true} autoRotateSpeed={0.5} />
                <Effects disableGamma>
                    <unrealBloomPass args={[new THREE.Vector2(256, 256), 1.6, 0.5, 0]} />
                </Effects>
            </Canvas>
        </div>
    );
}