from pipeline_b.mitmproxy_addon import _extract_multipart_images

boundary = '------------------------1234567890'
body = (
    b'--' + boundary.encode() + b'\r\n' +
    b'Content-Disposition: form-data; name="file"; filename="stego_output.png"\r\n' +
    b'Content-Type: image/png\r\n\r\n' +
    b'fakeimagecontent\r\n' +
    b'--' + boundary.encode() + b'--\r\n'
)
ct = f'multipart/form-data; boundary={boundary}'
print('Result 1:', _extract_multipart_images(body, ct))

body_kali = (
    b'--------------------------1234567890\r\n' +
    b'Content-Disposition: form-data; name="file"; filename="stego_output.png"\r\n' +
    b'Content-Type: image/png\r\n\r\n' +
    b'fakeimagecontent\r\n' +
    b'--------------------------1234567890--\r\n'
)
print('Result 2:', _extract_multipart_images(body_kali, ct))
