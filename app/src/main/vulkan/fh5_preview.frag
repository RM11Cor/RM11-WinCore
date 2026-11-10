#version 450
layout(set=0,binding=0) uniform sampler2D tex;
layout(push_constant) uniform Config {
    int grayscale;
} pc;
layout(location=0) in vec2 uv;
layout(location=0) out vec4 color;
void main() {
    vec4 texel = texture(tex, uv);
    color = pc.grayscale == 1 ? vec4(texel.rrr, 1.0) : vec4(texel.rgb,1.0);
}
