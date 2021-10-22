# Part B - Congestion Control

## (a) Top 10 cwnd
The top 10 congestion windows are as follows:

| Flow | Top 10 congestion windows (in number of packets) |
| --- | --- | 
| Flow 1 | 8, 9, 10, 11, 12, 13, 14, 13, 12, 11 | 
| Flow 2 | 8, 9, 8, 11, 12, 11, 10, 12, 13, 12 | 
| Flow 3 | 8, 9, 8, 7, 6, 5, 4, 3, 2, 1 | 

The congestion windows are estimated at the sender since sender is sending packets and has initiated the connection, so it will be responsible for congestion control while sending packets into the network.

**Strategy to compute congestion windows:**
For every flow, I maintain the highest sequence number sent till now and as soon as an ack is received, 1 RTT is done. Hence, at this moment, I subtract the received ack number from the highest sequence number and append the result to the congestion windows list. This is how I am estimating the congestion window at every RTT.

## (b) Retransmissions
| Flow | Triple duplicate ack (no of pkts) | Timeout (no of pkts) |
| --- | --- | --- |
| Flow 1 | 2 | 2 |
| Flow 2 | 36 | 59 |
| Flow 3 | 0 | 1 |

Strategy to compute retransmissions:

* **Triple duplicate acks:** I maintained the sent sequence numbers in a dictionary and calculate the same ack numbers received in different acknowledgements. If the count of ack numbers becomes 3, then that means that the loss occurred due to triple duplicate acks. I added the count of sent sequence numbers - 1 to calculate the loss.
* **Timeout:** I calculated the total loss as explained in Part A. I also computed the triple duplicate ack loss as explained above. The loss which is not due to triple duplicate ack is due to timeout. Hence the subtract the triple duplicate ack loss from the total loss to get the timeout loss.