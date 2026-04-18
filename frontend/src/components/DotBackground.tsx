'use client';
import { useEffect, useRef, useState } from 'react';

interface Dot {
    x: number; y: number; baseX: number; baseY: number;
    vx: number; vy: number; radius: number; opacity: number;
    pulseSpeed: number; pulseOffset: number;
    distToMouse: number; 
}

export function DotBackground() {
    const canvasRef = useRef<HTMLCanvasElement>(null);
    const mouseRef = useRef({ x: -9999, y: -9999 });
    const dotsRef = useRef<Dot[]>([]);
    const animRef = useRef<number>(0);
    
    const [active, setActive] = useState(true);

    useEffect(() => {
        const canvas = canvasRef.current!;
        const ctx = canvas.getContext('2d', { alpha: false })!;
        const SPACING = 28, MOUSE_RADIUS = 140, REPEL_STRENGTH = 45, CONNECTION_DIST = 90;

        function initDots() {
            const dots: Dot[] = [];
            const cols = Math.ceil(canvas.width / SPACING) + 1;
            const rows = Math.ceil(canvas.height / SPACING) + 1;
            for (let i = 0; i < cols; i++) {
                for (let j = 0; j < rows; j++) {
                    const bx = i * SPACING, by = j * SPACING;
                    dots.push({
                        x: bx + (Math.random() - 0.5) * 6, y: by + (Math.random() - 0.5) * 6,
                        baseX: bx, baseY: by,
                        vx: (Math.random() - 0.5) * 0.08, vy: (Math.random() - 0.5) * 0.08,
                        radius: 1.2 + Math.random() * 0.8, opacity: 0.18 + Math.random() * 0.28,
                        pulseSpeed: 0.003 + Math.random() * 0.005, pulseOffset: Math.random() * Math.PI * 2,
                        distToMouse: 9999
                    });
                }
            }
            dotsRef.current = dots;
        }

        let prevWidth = window.innerWidth;
        function resize() {
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;
            
            if (dotsRef.current.length === 0 || Math.abs(window.innerWidth - prevWidth) > 50) {
                initDots();
                prevWidth = window.innerWidth;
            }
        }

        function draw(time: number) {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            const mx = mouseRef.current.x, my = mouseRef.current.y;
            const dots = dotsRef.current;
            
            const nearDots: Dot[] = [];
            
            for (let i = 0; i < dots.length; i++) {
                const d = dots[i];
                d.vx += (Math.random() - 0.5) * 0.004; 
                d.vy += (Math.random() - 0.5) * 0.004;
                d.vx *= 0.96; 
                d.vy *= 0.96;
                d.vx += (d.baseX - d.x) * 0.0015; 
                d.vy += (d.baseY - d.y) * 0.0015;
                
                const dx = d.x - mx, dy = d.y - my;
                const dist = Math.hypot(dx, dy);
                d.distToMouse = dist;

                if (dist < MOUSE_RADIUS) {
                    const force = (1 - dist / MOUSE_RADIUS) * (1 - dist / MOUSE_RADIUS) * REPEL_STRENGTH;
                    d.vx += (dx / dist) * force * 0.06; 
                    d.vy += (dy / dist) * force * 0.06;
                }

                d.x += d.vx; 
                d.y += d.vy;

                if (dist < MOUSE_RADIUS * 1.5) {
                    nearDots.push(d);
                }
            }

            ctx.lineWidth = 0.5;
            for (let i = 0; i < nearDots.length; i++) {
                for (let j = i + 1; j < nearDots.length; j++) {
                    const d1 = nearDots[i];
                    const d2 = nearDots[j];
                    const dist = Math.hypot(d1.x - d2.x, d1.y - d2.y);
                    if (dist < CONNECTION_DIST) {
                        const alpha = (1 - dist / CONNECTION_DIST) * 0.18 * (1 - d1.distToMouse / (MOUSE_RADIUS * 1.5));
                        ctx.beginPath(); 
                        ctx.moveTo(d1.x, d1.y); 
                        ctx.lineTo(d2.x, d2.y);
                        ctx.strokeStyle = `rgba(20,241,149,${alpha})`; 
                        ctx.stroke();
                    }
                }
            }

            for (let i = 0; i < dots.length; i++) {
                const d = dots[i];
                const pulse = Math.sin(time * d.pulseSpeed + d.pulseOffset) * 0.15;
                const isNear = d.distToMouse < MOUSE_RADIUS;
                const proximityBoost = isNear ? (1 - d.distToMouse / MOUSE_RADIUS) * 0.5 : 0;
                
                const finalOpacity = Math.min(1, d.opacity + pulse + proximityBoost);
                const finalRadius = d.radius + (isNear ? (1 - d.distToMouse / MOUSE_RADIUS) * 1.5 : 0);

                ctx.beginPath(); 
                ctx.arc(d.x, d.y, finalRadius, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(20,241,149,${finalOpacity})`; 
                ctx.fill();

                if (isNear) {
                    ctx.beginPath();
                    ctx.arc(d.x, d.y, finalRadius * 3, 0, Math.PI * 2);
                    ctx.fillStyle = `rgba(20,241,149,${finalOpacity * 0.15})`;
                    ctx.fill();
                }
            }

            animRef.current = requestAnimationFrame(draw);
        }

        const onMouseMove = (e: MouseEvent) => { mouseRef.current = { x: e.clientX, y: e.clientY }; };
        const onMouseLeave = () => { mouseRef.current = { x: -9999, y: -9999 }; };
        const onProcessEvent = (e: any) => { setActive(!e.detail.active); };

        window.addEventListener('mousemove', onMouseMove);
        window.addEventListener('mouseleave', onMouseLeave);
        window.addEventListener('resize', resize);
        
        window.addEventListener('darkdrop-processing-create', onProcessEvent);
        window.addEventListener('darkdrop-processing-claim', onProcessEvent);

        resize();
        animRef.current = requestAnimationFrame(draw);

        return () => {
            cancelAnimationFrame(animRef.current);
            window.removeEventListener('mousemove', onMouseMove);
            window.removeEventListener('mouseleave', onMouseLeave);
            window.removeEventListener('resize', resize);
            window.removeEventListener('darkdrop-processing-create', onProcessEvent);
            window.removeEventListener('darkdrop-processing-claim', onProcessEvent);
        };
    }, []);

    return <canvas ref={canvasRef} className={`fixed inset-0 z-0 pointer-events-none transition-opacity duration-1000 ${active ? 'opacity-85' : 'opacity-0'}`} />;
}