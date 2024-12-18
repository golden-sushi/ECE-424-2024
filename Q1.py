import random

#Part 4 encoding algorithm
def encode(k, message_lengths, messages):
    #first 5 bits for the number of messages k
    encoded_message = format(k, '05b')
    
    for i in range(k):
        ni = message_lengths[i]
        # Next 8 bits for the length ni of each message
        encoded_message += format(ni, '08b')
        # Next ni bits for the content of the message
        encoded_message += messages[i]
    
    return encoded_message
#Part 4 Decoding algorithm
def decode(encoded_message):
    #first 5 bits for the number of messages k
    k = int(encoded_message[:5], 2)
    decoded_messages = []
    pos = 5
    
    for i in range(k):
        # Next 8 bits for the length of message ni
        ni = int(encoded_message[pos:pos+8], 2)
        pos += 8
        # Next ni bits for the content of the message
        message = encoded_message[pos:pos+ni]
        decoded_messages.append(message)
        pos += ni
    
    return decoded_messages

#Testing - for part 5
k = random.randint(1, 32) # randomly choosing number for k
message_lengths = [random.randint(1, 5) for _ in range(k)]
messages = [format(random.getrandbits(ni), f'0{ni}b') for ni in message_lengths]

encoded = encode(k, message_lengths, messages)
decoded = decode(encoded)

print(f"Original Messages: {messages}")
print(f"Encoded: {encoded}")
print(f"Decoded: {decoded}")
