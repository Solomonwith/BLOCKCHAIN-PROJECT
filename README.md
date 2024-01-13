Step 1
On your windows search bar, bottom left corner type “cmd” without the quotes and press enter.
The above command should open the command line prompt (black screen) in your default directory. The default directory (specific to your laptop) should be:
C:\Users\user

Step 2
Navigate to your project directory (folder which we already set up) using the following command:
cd documents\blockchain\blockchain
and press enter.
If you type “dir” and press enter you should be able to see all files within the directory, these include the templates directory, virt (which is the virtual environment directory) and the main project file which is blockchain.py.. etc..

Step 3 
We now need to activate our virtual environment (the virtual environment is like just a container where we installed all the system libraries and dependencies) we need to activate this environment so that we can access the full functionality of Web application.
Ok having said that on the command line type:
virt\Scripts\activate
once you press enter. You should see:
(virt) c:\Users\user\Documents\blockchain\blockchain>
The (virt) shows that the virtual environment has been activated.

Step 4
Type:
python blockchain.py and press enter to run your Flask Web application

Step 5
Now in the browser of your choice you can now type:
localhost:5000
and press enter you should be presented with the login page with the browser
NB: go through the above steps after you have made sure that the IPFS client and Ganache are running:
