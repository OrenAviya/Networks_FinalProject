# Networks_FinalProject
# aviya oren & neta cohen
Final project in communication networks course
that project has two parts: both in the PDF 

1. The dry part - conclution of the paper "Practical Traffic Analysis Attacks on Secure Messaging Applications".

2. The wet part - Record communication in 4 instant messaging (IM) groups.

   (we chose WhatsApp Web on a PC, and Wireshark. also we append a code in python which sniff the packets traffic and create graphs to show our result)

We generate for each such group plots of the inter-message delays and the message sizes, 
similarly to those presented in the paper. That plots exist in each group folder.

Then we try to deduce the groups we take part in, using the techniques detailed in the paper.

# Instructions for running code:

1. Download the "sniffer.py"

2. Check what is the ip of your web and the channel you whant to check.

3. Change the following fields according to your needs:
"target_ipv6" = your target channel IP.
"Curr_IP_adress" = your ip
"file_place_and_name" = where you want tosave the output file
"output_folder" = place to save the plots
"time_out" = you can change the time you want to run the code, in seconds (for 10 minuets difined time_out to 600)

5. press "run" . or use the commend prompt to run the code file.
