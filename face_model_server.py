from wsgiref.simple_server import make_server
import cgi, json

def root(environ, start_response):
    start_response("200 OK", [('Content-type', 'application/json')])
    return [json.dumps(data).encode()]

def face_upload(environ, start_response):
    length = int(environ.get('CONTENT_LENGTH', 0))
    content = environ['wsgi.input'].read(length).decode()
    data = cgi.parse_qs(content)
    start_response("200 OK", [('Content-type', 'application/json')])
    return [json.dumps(data).encode()]

data = {'success': True, 'error': None}
pages = {
    '/': root,
    '/faceupload': face_upload
    }

def application(environ, start_response):
    path = environ['PATH_INFO']
    if path in pages:
        return pages[path](environ, start_response)
    start_response('404 NOT FOUND', [])
    return [b'']

def main():
    httpd = make_server('localhost', 5000, application)
    print("Serving WSGI on localhost:5000...")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("Server aborted.")

if __name__ == "__main__": main()
