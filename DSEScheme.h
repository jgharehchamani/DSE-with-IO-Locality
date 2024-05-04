/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   DSEScheme.h
 * Author: jgc
 *
 * Created on April 21, 2024, 2:38 PM
 */

#ifndef DSESCHEME_H
#define DSESCHEME_H

#include <iostream>
#include <vector>

class DSEScheme {
public:
    DSEScheme(){};    
    virtual void update(OP op, std::string keyword, int ind, bool setup)=0;
    virtual void endSetup()=0;
    virtual ~DSEScheme(){};
    virtual bool setupFromFile(std::string filename)=0;
    virtual void beginSetup()=0;
    virtual std::vector<int> search(std::string keyword)=0;
    double totalSearchTime, totalUpdateTime;

};

#endif /* DSESCHEME_H */

