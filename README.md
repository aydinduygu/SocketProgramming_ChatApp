# SocketProgramming_ChatApp

This is a simple chat program runs on the console. TCP and UDP socket programming is used to build this program.


Server Side:

On the server side, server waits for new TCP connection or new UDP datagram packet to handle.
Once one of them received, new thread is created to handle them.
Server checks if a user is online by controlling whether a recent hello message is received from him/her or not.

On the client side when the app is first started, a menu with three options is greeting the user:

1.	Login
2.	Register
3.	Exit

If user enters 2 then the program prompts user to enter username and password for registering.
And if a user enters a unique username that has not been taken by anyone before and a password, 
the program starts to carry out the registration process. 

However if user enters 1 to the initial menu this time the program prompts user again to enter a username and password but this time starts the login process.
For a successful login both username must be registered before and the password must match with the registered one.
In addition, if a registered user is already logged in, it prevents the second log in and shows an error.

However if user tries to get a username that is taken before, the program will not allow it.

If user enters a wrong password or tries to login with an unregistered username, the program will not accept.

After successful login program prompts user to enter the username of the person that he/she wants to have a chat with, 
if user supplies a username, client program triggers a search on the server among registered users,
as soon as user found ip address of the user is sent to requester and  a chat request is sent to this user.

If user tries to log in to an already logged in account, he/she receives an error.

GROUP CHAT

While two users are chatting they can invite other users to the chat, so that they can start a group chat.

LOG

The program stores logs for the server and for every client separately.
Each action from both server side and client side are being logged to these files during runtime.
To achieve this, we created a Log class and created an instance of it inside it. Each time an action happens,
server or client gets this instance and uses it to store the action into the log file.

Below we shared two examples of server log and a client log.


