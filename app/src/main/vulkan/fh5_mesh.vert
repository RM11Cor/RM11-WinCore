#version 450
// FH5 M23: physically coherent Z-up orbit camera, perspective depth and dual light.
layout(location=0) in vec3 position;
layout(location=1) in vec3 normal;
layout(location=2) in vec2 uv;
layout(push_constant) uniform Camera {
    // yaw, zoom, elevation, reserved
    vec4 angleScale;
    // diagnostic material color (RGB), alpha
    vec4 color;
} pc;
layout(location=0) out vec3 litColor;

void main() {
    const float PI=3.141592653589793;
    // FH5 car data is X=left/right, Y=front/back, Z=up.
    // Bounds measured from M22 FHMS data: X ~+-0.79, Y -1.98..2.07, Z -0.05..1.29.
    vec3 centered=position-vec3(0.0,0.04,0.62);
    float yaw=pc.angleScale.x;
    float elevation=clamp(pc.angleScale.z,0.10,1.22);
    float cosine=cos(yaw), sine=sin(yaw);
    float cp=cos(elevation), sp=sin(elevation);
    vec3 cameraRight=vec3(cosine,-sine,0.0);
    vec3 cameraUp=vec3(-sine*sp,-cosine*sp,cp);
    vec3 towardCamera=vec3(sine*cp,cosine*cp,sp);
    float cameraDistance=6.5;
    float depth=max(0.11,cameraDistance-dot(centered,towardCamera));
    float zoom=clamp(pc.angleScale.y,0.70,1.45);
    float focal=2.2*zoom;
    float nearPlane=0.10,farPlane=24.0;
    float projectionZ=(farPlane/(farPlane-nearPlane))*depth
                      -(farPlane*nearPlane/(farPlane-nearPlane));
    // Vulkan has Y-down for positive-height viewports. Flip world-up here.
    gl_Position=vec4(dot(centered,cameraRight)*focal,
                    -dot(centered,cameraUp)*focal,projectionZ,depth);

    vec3 n=normalize(normal);
    vec3 key=normalize(vec3(-0.52,0.31,0.83));
    vec3 fill=normalize(vec3(0.58,-0.55,0.56));
    float light=0.34 + 0.55*max(dot(n,key),0.0)
                     + 0.21*max(dot(n,fill),0.0);
    vec3 halfVector=normalize(key+towardCamera);
    float sheen=0.09*pow(max(dot(n,halfVector),0.0),28.0);
    litColor=clamp(pc.color.rgb*light+vec3(sheen),0.0,1.0);
}
