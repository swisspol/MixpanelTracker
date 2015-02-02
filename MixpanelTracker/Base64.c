//
//  Created by Matt Gallagher on 2009/06/03.
//  Copyright 2009 Matt Gallagher. All rights reserved.
//
//  Permission is given to use this source code file, free of charge, in any
//  project, commercial or otherwise, entirely at your risk, with the condition
//  that any redistribution (in part or whole) of source code must retain
//  this copyright and permission notice. Attribution in compiled projects is
//  appreciated but not required.
//

#include <stdlib.h>
#include <stdbool.h>

static unsigned char base64EncodeLookup[65] =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

//
// Fundamental sizes of the binary and base64 encode/decode units in bytes
//
#define BINARY_UNIT_SIZE 3
#define BASE64_UNIT_SIZE 4

//
// NewBase64Encode
//
// Encodes the arbitrary data in the inputBuffer as base64 into a newly malloced
// output buffer.
//
//  inputBuffer - the source data for the encode
//  length - the length of the input in bytes
//  separateLines - if zero, no CR/LF characters will be added. Otherwise
//    a CR/LF pair will be added every 64 encoded chars.
//  outputLength - if not-NULL, on output will contain the encoded length
//    (not including terminating 0 char)
//
// returns the encoded buffer. Must be free'd by caller. Length is given by
//  outputLength.
//
char *NewBase64Encode(
  const void *buffer,
  size_t length,
  bool separateLines,
  size_t *outputLength)
{
  const unsigned char *inputBuffer = (const unsigned char *)buffer;
  
  #define OUTPUT_LINE_LENGTH 64
  #define INPUT_LINE_LENGTH ((OUTPUT_LINE_LENGTH / BASE64_UNIT_SIZE) * BINARY_UNIT_SIZE)
  #define CR_LF_SIZE 2
  
  //
  // Byte accurate calculation of final buffer size
  //
  size_t outputBufferSize =
      ((length / BINARY_UNIT_SIZE)
        + ((length % BINARY_UNIT_SIZE) ? 1 : 0))
          * BASE64_UNIT_SIZE;
  if (separateLines)
  {
    outputBufferSize +=
      (outputBufferSize / OUTPUT_LINE_LENGTH) * CR_LF_SIZE;
  }
  
  //
  // Include space for a terminating zero
  //
  outputBufferSize += 1;

  //
  // Allocate the output buffer
  //
  char *outputBuffer = (char *)malloc(outputBufferSize);
  if (!outputBuffer)
  {
    return NULL;
  }

  size_t i = 0;
  size_t j = 0;
  const size_t lineLength = separateLines ? INPUT_LINE_LENGTH : length;
  size_t lineEnd = lineLength;
  
  while (true)
  {
    if (lineEnd > length)
    {
      lineEnd = length;
    }

    for (; i + BINARY_UNIT_SIZE - 1 < lineEnd; i += BINARY_UNIT_SIZE)
    {
      //
      // Inner loop: turn 48 bytes into 64 base64 characters
      //
      outputBuffer[j++] = base64EncodeLookup[(inputBuffer[i] & 0xFC) >> 2];
      outputBuffer[j++] = base64EncodeLookup[((inputBuffer[i] & 0x03) << 4)
        | ((inputBuffer[i + 1] & 0xF0) >> 4)];
      outputBuffer[j++] = base64EncodeLookup[((inputBuffer[i + 1] & 0x0F) << 2)
        | ((inputBuffer[i + 2] & 0xC0) >> 6)];
      outputBuffer[j++] = base64EncodeLookup[inputBuffer[i + 2] & 0x3F];
    }
    
    if (lineEnd == length)
    {
      break;
    }
    
    //
    // Add the newline
    //
    outputBuffer[j++] = '\r';
    outputBuffer[j++] = '\n';
    lineEnd += lineLength;
  }
  
  if (i + 1 < length)
  {
    //
    // Handle the single '=' case
    //
    outputBuffer[j++] = base64EncodeLookup[(inputBuffer[i] & 0xFC) >> 2];
    outputBuffer[j++] = base64EncodeLookup[((inputBuffer[i] & 0x03) << 4)
      | ((inputBuffer[i + 1] & 0xF0) >> 4)];
    outputBuffer[j++] = base64EncodeLookup[(inputBuffer[i + 1] & 0x0F) << 2];
    outputBuffer[j++] =  '=';
  }
  else if (i < length)
  {
    //
    // Handle the double '=' case
    //
    outputBuffer[j++] = base64EncodeLookup[(inputBuffer[i] & 0xFC) >> 2];
    outputBuffer[j++] = base64EncodeLookup[(inputBuffer[i] & 0x03) << 4];
    outputBuffer[j++] = '=';
    outputBuffer[j++] = '=';
  }
  outputBuffer[j] = 0;
  
  //
  // Set the output length and return the buffer
  //
  if (outputLength)
  {
    *outputLength = j;
  }
  return outputBuffer;
}
