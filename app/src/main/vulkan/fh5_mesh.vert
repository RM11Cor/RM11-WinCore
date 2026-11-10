#version 450
layout(location=0) in vec3 position;
layout(location=1) in vec3 normal;
layout(location=2) in vec2 uv;
layout(push_constant) uniform Camera { vec4 angleScale; vec4 color; } pc;
layout(location=0) out vec3 litColor;
void main() {
    vec3 p=position-vec3(0.0,0.0,0.60);
    float a=pc.angleScale.x;
    float c=cos(a), s=sin(a);
    vec3 q=vec3(c*p.x-s*p.y,s*p.x+c*p.y,p.z);
    float x=(0.77*q.x + 0.64*q.y)/2.55 * pc.angleScale.y;
    float y=(-0.38*q.x + 0.45*q.y + 0.79*q.z)/1.90 * pc.angleScale.y;
    float depth=clamp(0.50 + (0.35*q.x-0.39*q.y-0.65*q.z)/5.0,0.01,0.99);
    gl_Position=vec4(x,y,depth,1.0);
    vec3 n=normalize(vec3(c*normal.x-s*normal.y,s*normal.x+c*normal.y,normal.z));
    float diffuse=max(dot(n,normalize(vec3(0.35,-0.5,0.78))),0.0);
    float lighting=0.38+0.62*diffuse;
    litColor=pc.color.rgb * lighting;
}
