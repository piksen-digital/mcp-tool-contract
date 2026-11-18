FROM apify/actor-node:20

COPY --chown=myuser:myuser package*.json ./
RUN npm ci --omit=dev
COPY --chown=myuser:myuser . ./

CMD ["npm", "run", "start"]
