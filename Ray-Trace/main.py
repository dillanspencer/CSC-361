import matplotlib.pyplot as plt
import re
import sys
from structs import *

width = 300
height = 200

max_depth = 3

camera = np.array([0, 0, 1])
ratio = float(width) / height
screen = (-1, 1 / ratio, 1, -1 / ratio)  # left, top, right, bottom


def main():
    file = sys.argv[1]
    f = open(file, "r")
    lines = f.readlines()
    scene = parse(lines)
    objects = [s.output() for s in scene.spheres]
    lights = [s.output() for s in scene.lights]
    image = np.zeros((height, width, 3))
    for i, y in enumerate(np.linspace(screen[1], screen[3], height)):
        for j, x in enumerate(np.linspace(screen[0], screen[2], width)):
            # screen is on origin
            pixel = np.array([x, y, 0])
            origin = camera
            direction = normalize(pixel - origin)

            color = np.zeros((3))
            reflection = 1

            for light in lights:
                for k in range(max_depth):
                    # check for intersections
                    nearest_object, min_distance = nearest_intersected_object(objects, origin, direction)
                    if nearest_object is None:
                        break

                    intersection = origin + min_distance * direction
                    normal_to_surface = normalize(intersection - nearest_object['center'])
                    shifted_point = intersection + 1e-5 * normal_to_surface

                    intersection_to_light = normalize(light['position'] - shifted_point)

                    _, min_distance = nearest_intersected_object(objects, shifted_point, intersection_to_light)
                    intersection_to_light_distance = np.linalg.norm(light['position'] - intersection)
                    is_shadowed = min_distance < intersection_to_light_distance

                    if is_shadowed:
                        break

                    illumination = np.zeros((3))

                    # ambiant
                    illumination += nearest_object['ambient'] * light['ambient']

                    # diffuse
                    illumination += nearest_object['diffuse'] * light['diffuse'] * np.dot(intersection_to_light,
                                                                                          normal_to_surface)

                    # specular
                    intersection_to_camera = normalize(camera - intersection)
                    H = normalize(intersection_to_light + intersection_to_camera)
                    illumination += nearest_object['specular'] * light['specular'] * np.dot(normal_to_surface, H) ** (
                            nearest_object['shininess'] / 4)

                    # reflection
                    color += reflection * illumination
                    reflection *= nearest_object['reflection']

                    origin = shifted_point
                    direction = reflected(direction, normal_to_surface)

                image[i, j] = np.clip(color, 0, 1)
        print("%d/%d" % (i + 1, height))

    plt.imsave('image.png', image)


def normalize(vector):
    return vector / np.linalg.norm(vector)


def reflected(vector, axis):
    return vector - 2 * np.dot(vector, axis) * axis


def sphere_intersect(center, radius, ray_origin, ray_direction):
    b = 2 * np.dot(ray_direction, ray_origin - center)
    c = np.linalg.norm(ray_origin - center) ** 2 - radius ** 2
    delta = b ** 2 - 4 * c
    if delta > 0:
        t1 = (-b + np.sqrt(delta)) / 2
        t2 = (-b - np.sqrt(delta)) / 2
        if t1 > 0 and t2 > 0:
            return min(t1, t2)
    return None


def nearest_intersected_object(objects, ray_origin, ray_direction):
    distances = [sphere_intersect(obj['center'], obj['radius'], ray_origin, ray_direction) for obj in objects]
    nearest_object = None
    min_distance = np.inf
    for index, distance in enumerate(distances):
        if distance and distance < min_distance:
            min_distance = distance
            nearest_object = objects[index]
    return nearest_object, min_distance


def parse(lines):
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

    for line in lines:
        line = line.strip()
        # print(line)
        if re.search("^NEAR", line):
            near = re.search("[+-]?\d+(?:\.\d+)?", line).group(0)
        elif re.search("^LEFT", line):
            left = re.search("[+-]?\d+(?:\.\d+)?", line).group(0)
        elif re.search("^RIGHT", line):
            right = re.search("[+-]?\d+(?:\.\d+)?", line).group(0)
        elif re.search("^BOTTOM", line):
            bottom = re.search("[+-]?\d+(?:\.\d+)?", line).group(0)
        elif re.search("^TOP", line):
            top = re.search("[+-]?\d+(?:\.\d+)?", line).group(0)
        elif re.search("^RES", line):
            res = re.findall("[+-]?\d+(?:\.\d+)?", line)
            res[0] = int(res[0])
            res[1] = int(res[1])
        elif re.search("^SPHERE", line):
            info = line.split()
            name = info[1]
            posx = float(info[2])
            posy = float(info[3])
            posz = float(info[4])
            sclx = float(info[5])
            scly = float(info[6])
            sclz = float(info[7])
            r = float(info[8])
            g = float(info[9])
            b = float(info[10])
            ka = float(info[11])
            kd = float(info[12])
            ks = float(info[13])
            kr = float(info[14])
            n = float(info[15])
            sphere = Sphere(name)
            sphere.set_position(posx, posy, posz)
            sphere.set_scale(sclx, scly, sclz)
            sphere.set_color(r, g, b)
            sphere.set_diffusion(kd)
            sphere.set_specular(ks)
            sphere.set_reflection(kr)
            spheres.append(sphere)

        elif re.search("^LIGHT", line):
            info = line.split()
            name = info[1]
            posx = float(info[2])
            posy = float(info[3])
            posz = float(info[4])
            lr = float(info[5])
            lg = float(info[6])
            lb = float(info[7])
            lght = Light(name, posx, posy, posz, lr, lg, lb)
            lights.append(lght)

        elif re.search("^BACK", line):
            info = line.split()
            r = float(info[1])
            g = float(info[2])
            b = float(info[3])
            back = [r, g, b]

        elif re.search("^AMBIENT", line):
            info = line.split()
            lr = float(info[1])
            lg = float(info[2])
            lb = float(info[3])
            ambient = [lr, lg, lb]

        elif re.search("^OUTPUT", line):
            info = line.split()
            output = info[1]

    scene = Scene(near, left, right, bottom, top, res, spheres, lights, back, ambient, output)
    return scene


if __name__ == '__main__':
    main()
