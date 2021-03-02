<!-- PROJECT LOGO -->
<br />
<p align="center">

  <h2 align="center">CSC 361 Programming Assignment 2</h2>

  <p align="center">
    The purpose of this project is to understand the details of state management in Transmission
7 Control Protocol (TCP). You are required to write a python program to analyze the TCP protocol
8 behavior.
    <br />
    <a href="https://github.com/DillanSpencer/CSC-361"><strong>All Projects From CSC 361 »</strong></a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary><h2 style="display: inline-block">Table of Contents</h2></summary>
  <ol>
    <li>
      <a href="#how-to-run-the-program">How to Run The Program</a>
    </li>
    <li>
      <a href="#getting-started">Outline</a>
      <ul>
        <li><a href="#requirements">Requirements</a></li>
        <li><a href="#deliverables">Deliverables</a></li>
        <li><a href="#output">Output</a></li>
      </ul>
    </li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## How To Run The Program


Here's a blank template to get started:

1. Python
 ```sh
 python main.py filename.cap
 ```
2. Python 3
```sh
 python3 main.py filename.cap
 ```

<!-- GETTING STARTED -->
## Project Outline

Assignment 2: TCP Traffic Analysis

### Requirements
You will be given a sample TCP trace file (sample-capture-file.cap). During the period traced, a
11 single web client accesses different web sites on the Internet. This trace is to be used for your own
12 test. TA might use a different trace file to test your code.
13 You need to write a python program for parsing and processing the trace file, and tracking TCP
14 state information. In this assignment, your code will be tested on the server linux.csc.uvic.ca. As
15 such, you are allowed to use only the Python packages of python3 currently installed on
16 linux.csc.uvic.ca. You are not allowed to install/use other third-party python packages.
17 Your program should process the trace file and compute summary information about TCP
18 connections. Note that a TCP connection is identified by a 4-tuple (IP source address, source port,
19 IP destination address, destination port), and packets can flow in both directions on a connection
20 (i.e., duplex). Also note that the packets from different connections can be arbitrarily interleaved
21 with each other in time, so your program will need to extract packets and associate them with the
22 correct connection

### Deliverables

For your final submission of your assignment, you are required to submit your source code. You
57 should include a readme file to tell TA how to run your code.
58 Zip your assignments (code) as one tar file using %tar -czvf on linux.csc.uvic.ca.
59 The marking scheme is as follows (refer to outputformat.pdf as well):
 
   
### Output


<!-- CONTACT -->
## Contact

Dillan Spenncer - [@dillan.spencer](https://www.instagram.com/dillan.spencer/) - dillan.spencer08@gmail.com

Project Link: [https://github.com/github_username/repo_name](https://github.com/DillanSpencer/CSC-361/a2)


