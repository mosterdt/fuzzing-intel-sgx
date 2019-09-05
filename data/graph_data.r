#!/usr/bin/Rscript
pause <- function() {invisible(scan("stdin", character(), nlines = 1, quiet = TRUE))}

args<-commandArgs(TRUE)
view_plot = is.na(args[1])

if (view_plot) X11(width=9, height=6) else pdf(file="graph_demo.pdf", width=9, height=5)

#-------------------------

data  <- read.csv("data_demo_1.csv", header=TRUE, sep=",")
papat <- read.csv("data_demo_2.csv", header=TRUE, sep=",")

data <- subset(data, run>0 & run < 10)
papat <- subset(papat, run>0 & run < 10)

test <- array(dim=max(data$t))
IDR <- function(x) { diff(quantile(as.numeric(x), c(0.1, 0.9), na.rm = FALSE, names = FALSE)) }

for (i in 1:max(data$t)) {
    buh <- subset(data, t==i)
    test[i] = (max(buh$offset) - min(buh$offset))
    #test[i] = IDR(buh$offset)

}

par(mfrow=c(2,1), cex=.7, mai=c(0.0,1,0.1,0.3), oma = c(4, 1, 2, 1))
layout(matrix(c(1, 1, 1, 1, 2), 5, 1, byrow = TRUE))

plot(data$t, data$offset, col=data$run+1, pch=1,
  xlab="Page time step", ylab="",
  xaxt='n',
  xlim=c(800, 1350)-000, ylim=c(0, 40))

#ptecol <- c(1,1,1,1)
#ptepch <- c(46,4,4,3)
#points(papat$t, papat$offset, pch=ptepch[papat$da+1], col=data$run+1)

legend(800, 40, bg="white", # title="",
  c("Enclave run number", "difference measure"), col=c(2,1), pch=c(15, NA), lty=c(NA, 1), cex=1.3, horiz=FALSE)

#--------------------------------

plot(-100, 0, xlim=c(800, 1350), ylim=c(0, 40),
  xlab="Page time step", ylab="")
lines(test, lty=1)


mtext("Memory footprint", side=3, line=0, cex=1, outer=TRUE)
mtext("Enclave Page Number", side=2, line=-4, cex=.8, outer=TRUE, adj=0.7)
mtext("Difference metric", side=2, line=-4, cex=.8, outer=TRUE, adj=0)
mtext("Page time step", side=1, line=2, cex=.8, outer=TRUE)
# 

#lines(data$ldp)
#abline(h = 0:15, untf = FALSE, col = "lightgray", lty = 3)
#points(data$rip/4096, col=4, pch="+")
#points(data$rsp/4096, col=4, pch="+")











if (view_plot) pause() else dev.off()
