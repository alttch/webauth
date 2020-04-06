DELETE
FROM webauth_user
WHERE confirmed='0'
  AND d_created < :d
