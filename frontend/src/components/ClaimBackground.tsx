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

const ZKVortex = () => {
    const meshRef = useRef<THREE.InstancedMesh>(null!);
    const count = 25000;
    const dummy = useMemo(() => new THREE.Object3D(), []);
    const pColor = useMemo(() => new THREE.Color(), []);
    const maxRadius = 250;

    const particlesData = useMemo(() => {
        const data = [];
        for (let i = 0; i < count; i++) {
            data.push({
                initialR: Math.random() * maxRadius,
                initialTheta: Math.random() * Math.PI * 2,
                speed: 10 + Math.random() * 40,
                wobbleSpeed: Math.random() * 5,
                baseHue: 0.38 + (Math.random() - 0.5) * 0.1,
            });
        }
        return data;
    }, []);

    const material = useMemo(() => new THREE.MeshBasicMaterial({ color: 0xffffff }), []);
    const geometry = useMemo(() => new THREE.SphereGeometry(0.08, 8, 8), []);

    useFrame((state) => {
        if (!meshRef.current) return;
        const time = state.clock.getElapsedTime() * 1.5;

        meshRef.current.rotation.y = time * 0.1;
        meshRef.current.rotation.z = Math.sin(time * 0.2) * 0.1;

        for (let i = 0; i < count; i++) {
            const p = particlesData[i];
            
            let r = p.initialR - (time * p.speed);
            r = ((r % maxRadius) + maxRadius) % maxRadius;

            const theta = p.initialTheta + time * (150 / (r + 10));

            const y = Math.pow(r, 1.3) * 0.2 - 60; 

            const chaos = (r / maxRadius) * 15; 
            const wobbleY = Math.sin(time * p.wobbleSpeed + i) * chaos;

            const x = Math.cos(theta) * r;
            const z = Math.sin(theta) * r;

            dummy.matrix.makeTranslation(x, y + wobbleY, z);
            meshRef.current.setMatrixAt(i, dummy.matrix);

            const depthIntensity = 1.0 - (r / maxRadius);
            const coreGlow = Math.pow(depthIntensity, 3.0);
            
            const finalLightness = 0.05 + coreGlow * 0.9;
            const finalHue = p.baseHue - (coreGlow * 0.1);

            pColor.setHSL(finalHue, 0.95, finalLightness);
            meshRef.current.setColorAt(i, pColor);
        }
        meshRef.current.instanceMatrix.needsUpdate = true;
        if (meshRef.current.instanceColor) meshRef.current.instanceColor.needsUpdate = true;
    });

    return <instancedMesh ref={meshRef} args={[geometry, material, count]} />;
};

export default function ClaimBackground() {
    const [active, setActive] = useState(false);

    useEffect(() => {
        const handleProcessEvent = (e: any) => setActive(e.detail.active);
        window.addEventListener('darkdrop-processing-claim', handleProcessEvent);
        return () => window.removeEventListener('darkdrop-processing-claim', handleProcessEvent);
    }, []);

    return (
        <div className={`fixed inset-0 z-0 pointer-events-none transition-opacity duration-1000 ${active ? 'opacity-90' : 'opacity-0'}`}>
            <Canvas camera={{ position: [0, 40, 220], fov: 60 }}>
                <fog attach="fog" args={['#000000', 100, 260]} />
                <ZKVortex />
                <OrbitControls enableZoom={false} enablePan={false} autoRotate={false} />
                <Effects disableGamma>
                    <unrealBloomPass args={[new THREE.Vector2(256, 256), 1.2, 0.5, 0]} />
                </Effects>
            </Canvas>
        </div>
    );
}