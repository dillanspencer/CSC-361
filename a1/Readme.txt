CSC 361 ASSIGNMENT 1
Name: Dillan Spencer
V-Number: V00914254

----- Run Program -----
Program can be run using exactly on parameter.
Run the command as following:

python SmartClient.py www.uvic.ca
or python3 SmartClient.py www.uvic.ca

----- Status Code Support -----
The program checks for these status codes:

200 OK:
	recognizes that the current requested version is supported and will 
	continue to check for HTTPS and HTTP 2.0.
	
301 Moved Permanently Redirect:
	uses regular expression to pull out the riderect location.
	checks header for https and decides if it supports HTTPS.
	sends another request using updated location.
	
302 URL Redirect
	uses regular expression to pull out the riderect location.
	checks header for https and decides if it supports HTTPS.
	sends another request using updated location.
	
400 Bad Request
	prints error to console
	quits program and prints any deliverables aquired
	
404 Domain not Found
	prints error to console
	quits program and prints any deliverables aquired
	
408 Request Timeout
	prints error to console
	quits program and prints any deliverables aquired
	
505 HTTP version not supported
	prints error to console
	generates a new request on HTTP 1.0 and port 80
	
Any other are handled by printing out the error code and exiting the program.

----- Cookies -----
Program grabs any cookies from the header using Regular Expression.
Prints them in form:

Cookie: <key>, <domain_name>, <expiry dat> (if any?)