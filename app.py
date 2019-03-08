#!/usr/bin/env python
import os
from PIL import Image
from io import BytesIO
from flask import Flask, render_template, Response, render_template_string, send_from_directory, request

import pandas as pd
from environment import ROOT_DIR

WIDTH = 600
HEIGHT = 800

app = Flask(__name__)

@app.route('/<path:filename>')
def image(filename):
    try:
        w = int(request.args['w'])
        h = int(request.args['h'])
    except (KeyError, ValueError):
        return send_from_directory('.', filename)

    try:
        im = Image.open(filename)
        im.thumbnail((w, h), Image.ANTIALIAS)
        io = BytesIO()
        im.save(io, format='JPEG')
        return Response(io.getvalue(), mimetype='image/jpeg')

    except IOError:
        abort(404)

    return send_from_directory('.', filename)


@app.route('/')
def images():
    images = []
    for root, dirs, files in os.walk('.'):
        for filename in [os.path.join(root, name) for name in files]:
            if not filename.endswith('.jpg'):
                continue
            im = Image.open(filename)
            w, h = im.size
            aspect = 1.0*w/h
            if aspect > 1.0*WIDTH/HEIGHT:
                width = min(w, WIDTH)
                height = width/aspect
            else:
                height = min(h, HEIGHT)
                width = height*aspect
            images.append({
                'width': int(width),
                'height': int(height),
                'src': filename
            })

    return render_template("preview.html", **{
        'images': images
    })

@app.route('/csv/<path:csvpath>')
def images_csv(csvpath):
    print(csvpath)
    images = []
    limit=1e8
    df = pd.read_csv(os.path.join('/',csvpath))
    df = df[df['target']==0]
    for i, row in df.iterrows():
        if i > limit:
            break
        filename = os.path.join(ROOT_DIR,row['img_path'])
        im = Image.open(filename)
        w, h = im.size
        aspect = 1.0*w/h
        if aspect > 1.0*WIDTH/HEIGHT:
            width = min(w, WIDTH)
            height = width/aspect
        else:
            height = min(h, HEIGHT)
            width = height*aspect
        images.append({
            'width': int(width),
            'height': int(height),
            'src': filename
        })
        i +=1
        print(row['img_path'])

    return render_template("preview.html", **{
        'images': images
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', threaded=True,debug=True)
