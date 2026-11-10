#version 450
layout(location=0) out vec2 uv;
vec2 vertices[3] = vec2[](vec2(-1.0,-1.0), vec2(3.0,-1.0), vec2(-1.0,3.0));
void main() {
    vec2 position = vertices[gl_VertexIndex];
    gl_Position = vec4(position, 0.0, 1.0);
    uv = (position + vec2(1.0)) * 0.5;
}
