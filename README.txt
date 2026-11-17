CERTIFICATE VERIFY  -  upload a certificate, get a QR code, scanning shows "Verified" + the document

SETUP + RUN (database is created automatically)
  1. cp .env.example .env      then edit .env: your MySQL user/password, admin password, institute name
  2. python3 app.py
  On first start the app creates the database 'certificate_verify' and the table by itself
  (the MySQL user must be allowed to create databases, e.g. root). Nothing to run in MySQL manually.
  Uploaded files stay in data/files/ ; certificate details are in MySQL.
  (Flask + mysql-connector are needed:  pip install flask mysql-connector-python)

USE
  1. Admin -> fill name / course / period, choose the certificate file (PDF, PNG or JPG) -> Upload.
  2. The list shows a QR code + link for that certificate. "Download QR" saves a PNG to print or
     place on the certificate (the Certificate Generator / PDF Editor can place it too).
  3. Anyone who scans the QR opens  <website>/v/<id>  : "Certificate Verified", the details and the document.
  4. Revoke = page shows "Revoked". Delete = removes the file; the QR then shows "Not Verified".

IMPORTANT - website address in the QR
  The QR contains the address typed in the "Public website address" box. A phone can only open it if
  that address is reachable from the phone:
    - same Wi-Fi test:   http://192.168.0.153:5000   (this computer's LAN address)
    - real use:          deploy this folder on a server with HTTPS, then set BASE_URL=https://yourdomain.com
  Make the final QR AFTER you know the final website address, because changing it later changes the QR.

DATA
  Back up the MySQL database AND the data/files/ folder (both are needed).
  Change the default password (admin123) before going public.
