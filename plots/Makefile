DATA=$(wildcard data/*.txt)

SOURCES=$(wildcard *.tex)

PDFS=$(SOURCES:.tex=.pdf)

PNGS=$(PDFS:.pdf=.png)



all: $(PNGS) $(PDFS)

%.pdf: %.tex $(DATA)
	pdflatex $<

%.png: %.pdf
	gs -sDEVICE=pngalpha -sBATCH -sNOPAUSE -r300 -sOutputFile=$@ $<

clean:
	rm -f $(PDFS)
	rm -f $(PNGS)
	rm *.log
	rm *.aux

.phony:
	all clean
