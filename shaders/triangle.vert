#version 450
layout(location = 0) out vec3 outColor;
void main() {
    const vec2 positions[3] = vec2[](vec2(0.0, -0.65), vec2(0.65, 0.65), vec2(-0.65, 0.65));
    const vec3 colors[3] = vec3[](vec3(1.0, 0.2, 0.2), vec3(0.15, 0.95, 0.3), vec3(0.2, 0.4, 1.0));
    gl_Position = vec4(positions[gl_VertexIndex], 0.0, 1.0);
    outColor = colors[gl_VertexIndex];
}
