// encryption :

cd assignment2/sender
gcc -o gsend gsend.c -lcrypto   //compile
./gsend    //run

/* (the encryption algorithm will work and generate two files, both located in file folder c. example.txt.uf and HMAC.txt.uf) */


//socket file transfer. First, server will send example.txt.uf and then it will send HMAC.txt.uf
//transfer the example.txt.uf
cd .. // return to the previous directory
gcc -o file_server file_server.c //compile file_server.c
./file_server ./c/example.txt.uf   // server will send example.txt.uf to the client


//open a new terminal
cd assignment2
gcc -o file_client file_client.c  //compile
./file_client 127.0.0.1 ./d/example.txt.uf  //receive the file

//transfer the HMAC.txt.uf

./file_server ./c/HMAC.txt.uf   // server will send HMAC.txt.uf to the client


//open a new terminal
cd assignment2
./file_client 127.0.0.1 ./d/HMAC.txt.uf  //receive the file


//decryption
cd assignment2/receiver
gcc -o grec grec.c -lcrypto   //compile
./grec    //run

/* (the decryption algorithm will work and generate one file,located in file folder d. That is the plaintext, example.txt */

/*By Lin 2019/9/18 */
