import numpy as np


class Sphere:

    def __init__(self, name):
        self.name = name
        self.x = 0
        self.y = 0
        self.z = 0
        self.scale_x = 1
        self.scale_y = 1
        self.scale_z = 1
        self.color = 0
        self.ka = 0.5
        self.kd = 0
        self.ks = 0
        self.kr = 0
        self.n = 0

    def set_position(self, x, y, z):
        self.x = x
        self.y = y
        self.z = z

    def set_scale(self, sx, sy, sz):
        self.scale_x = sx
        self.scale_y = sy
        self.scale_z = sz

    def set_color(self, r, g, b):
        self.ka = np.array([r, g, b])

    def set_diffusion(self, diff):
        self.kd = diff

    def set_specular(self, spec):
        self.ks = spec

    def set_reflection(self, ref):
        self.kr = ref

    def set_other(self, ka, kd, ks, kr):
        self.ka = ka
        self.kd = kd
        self.ks = ks
        self.kr = kr

    def output(self):
        return {'center': np.array([self.x, self.y, self.z]),
                'radius': 0.7, 'ambient': self.ka, 'diffuse': self.kd,
                'specular': self.ks, 'shininess': 100, 'reflection': self.kr}


class Light:
    name = None
    posx = 0
    posy = 0
    posz = 0
    lr = 0
    lg = 0
    lb = 0

    def __init__(self, name, posx, posy, posz, lr, lg, lb):
        self.name = name
        self.posx = posx
        self.posy = posy
        self.posz = posz
        self.lr = lr
        self.lg = lg
        self.lb = lb

    def set_position(self, x, y, z):
        self.posx = x
        self.posy = y
        self.posz = z

    def set_color(self, r, g, b):
        self.lr = r
        self.lg = g
        self.lb = b

    def output(self):
        return {'position': np.array([self.posx, self.posy, self.posz]),
                'ambient': np.array([self.lr, self.lg, self.lb]), 'diffuse': np.array([1, 1, 1]),
                'specular': np.array([1, 1, 1])}

    def print_light(self):
        print("LIGHTS:")
        print("name:", self.name)
        print("posx:", self.posx)
        print("posy:", self.posy)
        print("posz:", self.posz)
        print("lr:", self.lr)
        print("lg:", self.lg)
        print("lb:", self.lb)


class Scene:
    near = None
    left = None
    right = None
    bottom = None
    top = None
    res = None
    spheres = []
    lights = []
    back = None
    ambient = None
    output = None

    def __init__(self, near, left, right, bottom, top, res, spheres, lights, back, ambient, output):
        self.near = near
        self.left = left
        self.right = right
        self.bottom = bottom
        self.top = top
        self.res = res
        self.spheres = spheres
        self.lights = lights
        self.back = back
        self.ambient = ambient
        self.output = output

    def print_scene(self):
        print("NEAR:", self.near)
        print("LEFT:", self.left)
        print("RIGHT:", self.right)
        print("BOTTOM:", self.bottom)
        print("TOP:", self.top)
        print("RES:", self.res)
        for sphere in self.spheres:
            sphere.print_sphere()

        for light in self.lights:
            light.print_light()

        print("BACK:", self.back)
        print("AMBIENT:", self.ambient)
        print("OUTPUT:", self.output)

