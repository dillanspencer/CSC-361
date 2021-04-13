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
        self.ka = 0
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

    def set_color(self, color):
        self.color = color

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
